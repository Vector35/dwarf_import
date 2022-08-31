# Copyright(c) 2020-2022 Vector 35 Inc
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files(the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and / or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

import sys
import logging
import concurrent.futures
from uuid import UUID
from typing import List, Optional, Iterable, Set, MutableMapping
from collections import defaultdict
from .model import QualifiedName, Component
from .mapped_model import AnalysisSession
from .model.observer import Observer
from .model.concrete_elements import (
  Element,
  Variable,
  Constant,
  Function, LocalVariable, Parameter,
  Type, BaseType, CompositeType, EnumType, StructType, UnionType, ClassType,
  AliasType, PointerType, ArrayType, FunctionType, ConstType,
  VariableStorage, Field,
  VariadicType, VolatileType,
  PointerToMemberType, StringType
)
from .model.locations import LocationType
from .location_index import LocationIndex, VariableUpdate, VariableUpdateStatus
from .mapping import BinjaMap
import binaryninja as bn


def get_function_platform(fn: Function):
  if fn.arch == 'ARM':
    return bn.Platform['linux-armv7']
  elif fn.arch == 'Thumb':
    return bn.Platform['linux-thumb2']
  else:
    return None


def rank_of_type(ty: Type) -> int:
  if ty.name.is_empty:
    return 100
  elif isinstance(ty, BaseType):
    return 0
  elif isinstance(ty, EnumType):
    return 0
  elif isinstance(ty, AliasType):
    return rank_of_type(ty.resolve_alias())
  elif isinstance(ty, ArrayType):
    return rank_of_type(ty.element_type)
  elif isinstance(ty, CompositeType):
    for f in ty.fields():
      if isinstance(f, CompositeType):
        return 50
    ranks = [rank_of_type(f.field.type) for f in ty.fields()]
    return max(ranks) if len(ranks) > 0 else 0
  elif isinstance(ty, PointerToMemberType):
    return 100
  else:
    raise NotImplementedError(f'rank_of_type {ty.__class__.__name__}')


class BinjaBridge(Observer, bn.BinaryDataNotification):
  def __init__(self, session: AnalysisSession, parameters_mode: str = 'inferred',
               log_level=logging.INFO, parent_logger=None):
    Observer.__init__(self)
    bn.BinaryDataNotification.__init__(self)
    if parent_logger is not None:
      self._log = parent_logger.getChild('Bridge')
      self._log.setLevel(log_level)
    else:
      logging.basicConfig(level=log_level)
      self._log = logging.getLogger('bridge')
    self._session: AnalysisSession = session
    self._model = session.model
    self._mapping: BinjaMap = session.mapping
    self._parameters_mode = parameters_mode
    self._version_table: MutableMapping[UUID, int] = dict()
    self._s2b_types: MutableMapping[UUID, bn.Type] = dict()
    self._b2s_types: MutableMapping[bn.QualifiedName, Type] = dict()
    self._base_types: MutableMapping[bn.QualifiedName, bn.Type] = dict()
    self._builtin_types: Set[bn.QualifiedName] = set()
    self._typelib_defined_types = set()
    self._session.model.add_observer(self)
    self._binary_view: bn.BinaryView = session.binary_view
    self.statistics = defaultdict(int)
    self._batch_mode = False
    self._translation_executor = None

  def translate_model(self, max_workers=None):
    self.translate_model_types()

    for fn in self._session.model.functions:
      if fn.entry_addr is not None:
        self._binary_view.create_user_function(fn.entry_addr, get_function_platform(fn))

    self._log.debug('Waiting for auto analysis after defining types and functions...')
    self._binary_view.update_analysis_and_wait()

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
      self._translation_executor = executor

      futures = []
      for v in self._session.model.variables:
        futures.append(executor.submit(self._translate_variable, v))

      futures = []
      for fn in self._session.model.functions:
        futures.append(executor.submit(self._translate_function, fn))
      concurrent.futures.wait(futures)

      self._log.debug('Waiting for auto analysis after translating functions...')
      self._binary_view.update_analysis_and_wait()

      futures = []
      for fn in self._session.model.functions:
        futures.append(executor.submit(self._translate_function_signature, fn))
      concurrent.futures.wait(futures)

      self._translation_executor = None

    self._binary_view.commit_undo_actions()

  def cancel(self, wait: bool):
    if self._translation_executor is not None:
      self._translation_executor.shutdown(wait=wait, cancel_futures=True)

  def translate_model_types(self, overwrite: bool = False):
    if overwrite is False:
      self._typelib_defined_types = set(self._binary_view.types.keys())

    for ty in sorted(self._session.model.types, key=lambda ty: rank_of_type(ty)):
      self._translate_type(ty)

  def _translate_component(self, component: Component, **kwargs):
    self._log.debug(f'Translating component ("{component.name}")')

    num_created = 0
    for start in filter(None, map(lambda f: f.entry_addr, component.functions())):
      binja_function = self._binary_view.get_function_at(start)
      if binja_function is None:
        self._binary_view.create_user_function(start)
        num_created += 1
    if num_created > 0:
      self._log.debug(f'Created {num_created} new function(s).')
      self._log.debug('Waiting for auto analysis...')
      self._binary_view.update_analysis_and_wait()

    self._translate_component_elements(component, component.elements(), **kwargs)

  def _translate_component_elements(
    self,
    component: Component,
    elements: Iterable[Element],
    do_return_type=True
  ):
    mapped_functions = []
    for el in filter(self._mapping.is_newer, elements):
      if isinstance(el, Type):
        self._translate_type(el)
      elif isinstance(el, Variable):
        self._translate_variable(el)
      elif isinstance(el, Function):
        if self._translate_function(el):
          mapped_functions.append(el)
      elif isinstance(el, Constant):
        self._translate_constant(el)
      else:
        self._log.warning(f'untranslated element: {type(el)}')

    if do_return_type is True:
      self._log.debug('Waiting for auto analysis...')
      self._binary_view.update_analysis_and_wait()
      for function in mapped_functions:
        self._translate_function_signature(function)

  def _translate_constant(self, const: Constant):
    pass

  def _translate_variable(self, var: Variable):
    if not self._mapping.is_newer(var):
      return False

    self._version_table[var.uuid] = var.version
    self._log.debug(f'Translating variable ("{var.name}", {var.version}, {(var.addr if var.addr is not None else 0):x})')

    if var.addr is None or var.type is None:
      if var.addr is None:
        self._log.debug(f'Variable "{var.name}" has no address.')
      if var.type is None:
        self._log.debug(f'Variable "{var.name}" has no type.')
      self.statistics['num_globals_unresolved'] += 1
      return

    binja_type = self._construct_binja_type(var.type, as_specifier=True)

    binja_var = self._binary_view.get_data_var_at(var.addr)
    if binja_var is None or binja_var.type != binja_type:
      self._binary_view.define_user_data_var(var.addr, binja_type)
      binja_var = self._binary_view.get_data_var_at(var.addr)

    if binja_var is None:
      self._log.error(f'Unable to define variable "{var.name}" at 0x{var.addr:x}')
      self.statistics['num_globals_unresolved'] += 1
      return

    symbol = self._binary_view.get_symbol_at(var.addr)
    if symbol is None or symbol.short_name != var.name:
      self._binary_view.define_user_symbol(bn.Symbol(bn.SymbolType.DataSymbol, var.addr, str(var.name)))

    self.statistics['num_globals_resolved'] += 1

  def _translate_function(self, fn: Function) -> bool:
    if not self._mapping.is_newer(fn):
      return False

    self._version_table[fn.uuid] = fn.version
    self._log.debug(f'Translating function ("{fn.name}", {fn.version}, {fn.entry_addr:x})')
    if fn.entry_addr is None:
      return False
    binja_function = self._binary_view.get_function_at(fn.entry_addr)
    if binja_function is None:
      self._binary_view.create_user_function(fn.entry_addr)
      self._log.info('Updating analysis and waiting...')
      self._binary_view.update_analysis_and_wait()
      binja_function = self._binary_view.get_function_at(fn.entry_addr)
      if binja_function is None:
        self._log.warning(f'Unable to create a function at {fn.entry_addr:x}')
        self.statistics['num_functions_not_found'] += 1
        return False

    binja_function.can_return = bn.BoolWithConfidence(not fn.no_return)

    binja_symbol: bn.CoreSymbol = binja_function.symbol
    if fn.name.is_empty is False and binja_symbol.short_name != str(fn.name):
      self._rename_symbol(binja_symbol, str(fn.name))

    if binja_function.mlil is None:
      if binja_function.analysis_skipped:
        binja_function.analysis_skipped = False
        self._binary_view.update_analysis_and_wait()
        if binja_function.mlil is None:
          if binja_function.analysis_skipped:
            self._log.warning(
              f'Function skipped a: {binja_function.symbol.short_name}'
              f' (reason = {binja_function.analysis_skip_reason.name}, {binja_function.analysis_performance_info})')
            self.statistics['num_functions_skipped'] += 1
          return False
      else:
        self._binary_view.update_analysis_and_wait()
        if binja_function.mlil is None:
          if binja_function.analysis_skipped:
            self._log.warning(
              f'Function skipped b: {binja_function.symbol.short_name}'
              f' (reason = {binja_function.analysis_skip_reason.name}, {binja_function.analysis_performance_info})')
            self.statistics['num_functions_skipped'] += 1
            return False
        else:
          assert False, 'No MLIL, update did not fix, and analysis not skipped.'

    local_vars = LocationIndex(binja_function, fn.frame_base, self._log)
    if self._parameters_mode == 'inferred':
      for p in fn.parameters:
        self._translate_parameter(p, binja_function, local_vars)
    if fn.variables is not None:
      for v in fn.variables:
        self._translate_local_variable(v, binja_function, local_vars)

    if fn.inlined_functions:
      for inlined_function in fn.inlined_functions:
        self._translate_inlined_function(inlined_function, binja_function, local_vars)

    local_vars.propagate_names()
    self.statistics['num_functions_processed'] += 1
    return True

  def _translate_function_signature(self, fn: Function):
    self._log.debug(f'Translating function signature ("{fn.name}", {fn.version}, {fn.entry_addr:x})')

    if fn.entry_addr is None:
      return
    binja_fn = self._binary_view.get_function_at(fn.entry_addr)
    assert(isinstance(binja_fn, bn.Function))

    return_type = bn.Type.void()
    if fn.return_value is not None:
      return_type = self._construct_binja_type(fn.return_value.type, as_specifier=True)

    if self._parameters_mode == 'declared':
      self._translate_function_type(fn, binja_fn)

    elif self._parameters_mode == 'inferred':
      valid_parameter_names = [p.local_name for p in fn.parameters]
      binja_params = binja_fn.function_type.parameters
      any_matched = False
      n_args = len(binja_params)
      for i in range(n_args - 1, -1, -1):
        if binja_params[i].name in valid_parameter_names:
          n_args = i + 1
          any_matched = True
          break

      if not any_matched:
        self._translate_function_type(fn, binja_fn)
        return

      if n_args != len(binja_params) or fn.variadic:
        func_type: bn.FunctionType = binja_fn.function_type
        assert func_type.calling_convention
        binja_fn.function_type = bn.Type.function(
          return_type,
          binja_params[:n_args],
          func_type.calling_convention,
          fn.variadic,
          func_type.stack_adjustment)
        return

      if return_type != binja_fn.function_type.return_value:
        binja_fn.return_type = return_type

  def _translate_inlined_function(
    self,
    inlined_function: Function,
    binja_function: bn.Function,
    local_vars: LocationIndex
  ):
    for p in inlined_function.parameters:
      if p.name and p.name != 'this':
        self._translate_parameter(p, binja_function, local_vars)
    self._translate_function_elements(inlined_function, (), binja_function, local_vars)

  def _translate_function_elements(
    self,
    fn: Function,
    elements: Iterable[Element],
    binja_function: bn.Function,
    locals: LocationIndex
  ):
    for el in elements:
      if isinstance(el, LocalVariable):
        self._translate_local_variable(el, binja_function, locals)
      elif isinstance(el, Parameter):
        self._translate_parameter(el, binja_function, locals)
    if fn.inlined_functions is not None:
      for inlined_function in fn.inlined_functions:
        self._translate_inlined_function(inlined_function, binja_function, locals)

  def _translate_type(self, ty: Type):
    if not self._mapping.is_newer(ty):
      return
    if ty.uuid in self._s2b_types:
      return
    if ty.name.is_empty:
      return
    if ty.name in self._typelib_defined_types:
      return

    registered_name = bn.QualifiedName(ty.name)
    binja_type = self._construct_binja_type(ty)

    self._s2b_types[ty.uuid] = binja_type
    self._b2s_types[registered_name] = ty

    if registered_name in self._builtin_types:
      self._log.debug(f'Not translating built-in type {registered_name} as {binja_type} ({binja_type.type_class.name})')
      return

    if registered_name in self._binary_view.types:
      self._log.debug(
        f'Redefining {registered_name} as {binja_type} '
        f'(previously {self._binary_view.types[ty.name]})')
    self._binary_view.define_user_type(registered_name, binja_type)

  def is_refinement_of(self, a, b) -> bool:
    if a.name != b.name:
      return False
    if len(b.members) == 0 and len(a.members) > 0:
      return True
    return False

  def _generate_typeid(self, binja_name: bn.QualifiedName) -> str:
    typeid = self._binary_view.get_type_id(binja_name)
    if typeid is not None:
      return typeid

    self._binary_view.define_user_type(binja_name, bn.Type.void())
    typeid = self._binary_view.get_type_id(binja_name)
    assert(typeid is not None)
    return typeid

  def _construct_binja_type(self, ty: Type, as_specifier: bool = False) -> bn.Type:
    binja_type: Optional[bn.Type] = None
    binja_name = bn.QualifiedName(ty.name)

    if ty.uuid in self._s2b_types:
      if as_specifier and ty.name.is_anonymous is False:
        ntrc = bn.NamedTypeReferenceClass.UnknownNamedTypeClass
        if isinstance(ty, ClassType):
          ntrc = bn.NamedTypeReferenceClass.ClassNamedTypeClass
        elif isinstance(ty, StructType):
          ntrc = bn.NamedTypeReferenceClass.StructNamedTypeClass
        elif isinstance(ty, UnionType):
          ntrc = bn.NamedTypeReferenceClass.UnionNamedTypeClass
        elif isinstance(ty, EnumType):
          ntrc = bn.NamedTypeReferenceClass.EnumNamedTypeClass
        binja_type = bn.Type.named_type(
          bn.NamedTypeReferenceBuilder.create(
            name=binja_name,
            type_id=self._generate_typeid(binja_name),
            type_class=ntrc,
            width=(0 if ty.byte_size is None else ty.byte_size)
          )
        )
      else:
        binja_type = self._s2b_types[ty.uuid]
      return binja_type

    bv = self._binary_view
    assert(bv.arch)
    if isinstance(ty, BaseType):
      if binja_name in self._base_types:
        binja_type = self._base_types[binja_name]
      else:
        try:
          binja_type, _ = bv.parse_type_string(str(ty.name))
          self._base_types[binja_name] = binja_type
          self._builtin_types.add(binja_name)
        except Exception:
          if ty.byte_size is not None:
            binja_type = bn.Type.int(ty.byte_size, False)
            self._base_types[binja_name] = binja_type
            self._builtin_types.add(binja_name)
          else:
            binja_type = bn.Type.named_type(
              bn.NamedTypeReferenceBuilder.create(
                name=binja_name,
                type_id=self._generate_typeid(binja_name),
                width=0
              ),
            )
            self._base_types[binja_name] = binja_type
    elif isinstance(ty, PointerType):
      binja_target_type = self._construct_binja_type(ty.target_type, as_specifier=True)
      binja_ref_type = bn.ReferenceType.PointerReferenceType
      if ty.nullable is False:
        binja_ref_type = bn.ReferenceType.ReferenceReferenceType
      binja_type = bn.Type.pointer(bv.arch, binja_target_type, ref_type=binja_ref_type)
    elif isinstance(ty, ArrayType):
      binja_element_type = self._construct_binja_type(ty.element_type, as_specifier=True)
      count = 0 if ty.count is None else ty.count
      if count > 65535:
        count = 0
      binja_type = bn.Type.array(binja_element_type, count)
    elif isinstance(ty, EnumType):
      if as_specifier and ty.name.is_anonymous is False:
        ntrc = bn.NamedTypeReferenceClass.EnumNamedTypeClass
        binja_type = bn.Type.named_type(
          bn.NamedTypeReferenceBuilder.create(
            name=binja_name,
            type_id=self._generate_typeid(binja_name),
            type_class=ntrc,
            width=(0 if ty.byte_size is None else ty.byte_size)
          )
        )
      e = bn.EnumerationBuilder.create(members=[])
      for m in ty.enumerators:
        e.append(m.label, m.value)
      byte_size = (0 if ty.byte_size is None else ty.byte_size)
      binja_type = bn.Type.enumeration_type(bv.arch, e, byte_size)
    elif isinstance(ty, CompositeType):
      if as_specifier and ty.name.is_anonymous is False:
        ntrc = bn.NamedTypeReferenceClass.UnknownNamedTypeClass
        if isinstance(ty, ClassType):
          ntrc = bn.NamedTypeReferenceClass.ClassNamedTypeClass
        elif isinstance(ty, StructType):
          ntrc = bn.NamedTypeReferenceClass.StructNamedTypeClass
        elif isinstance(ty, UnionType):
          ntrc = bn.NamedTypeReferenceClass.UnionNamedTypeClass
        binja_type = bn.Type.named_type(
          bn.NamedTypeReferenceBuilder.create(
            name=binja_name,
            type_id=self._generate_typeid(binja_name),
            type_class=ntrc,
            width=(0 if ty.byte_size is None else ty.byte_size)
          )
        )
      else:
        if isinstance(ty, ClassType) or isinstance(ty, StructType):
          struct = bn.StructureBuilder.create()
          struct.type = bn.StructureVariant.StructStructureType
          if isinstance(ty, ClassType):
            struct.type = bn.StructureVariant.ClassStructureType
          if ty.byte_size is not None:
            struct.width = ty.byte_size
          for m in ty.fields():
            field_type = self._construct_binja_type(m.field.type, as_specifier=True)
            field_name = m.field.local_name
            if m.field.offset is not None:
              struct.insert(m.field.offset, field_type, field_name)
          binja_type = bn.Type.structure_type(struct)
        elif isinstance(ty, UnionType):
          union = bn.StructureBuilder.create()
          union.type = bn.StructureVariant.UnionStructureType
          if ty.byte_size is not None:
            union.width = ty.byte_size
          for m in ty.fields():
            field_type = self._construct_binja_type(m.field.type, as_specifier=as_specifier)
            field_name = m.field.local_name
            if m.field.offset is not None:
              union.insert(m.field.offset, field_type, field_name)
          binja_type = bn.Type.structure_type(union)
        else:
          assert(False)
    elif isinstance(ty, FunctionType):
      has_variable_args = False
      if ty.return_type is None:
        ret = bn.Type.void()
      else:
        ret = self._construct_binja_type(ty.return_type, as_specifier=True)
      params = []
      for param_type in ty.parameters:
        if isinstance(param_type, VariadicType):
          has_variable_args = True
        else:
          params.append(self._construct_binja_type(param_type, as_specifier=True))
      binja_type = bn.Type.function(ret, params, variable_arguments=has_variable_args)
    elif isinstance(ty, AliasType):
      binja_type = self._construct_binja_type(ty.type, as_specifier=not ty.type.name.is_anonymous)
    elif isinstance(ty, ConstType):
      binja_type = self._construct_binja_type(ty.type, as_specifier=True)
      temp = binja_type.mutable_copy()
      temp.const = True
      binja_type = temp.immutable_copy()
      assert(binja_type is not None)
    elif isinstance(ty, VolatileType):
      binja_type = self._construct_binja_type(ty.type, as_specifier=True)
      temp = binja_type.mutable_copy()
      temp.volatile = True
      binja_type = temp.immutable_copy()
      assert(binja_type is not None)
    elif isinstance(ty, PointerToMemberType):
      mp_struct = bn.StructureBuilder.create()
      mp_struct.type = bn.StructureVariant.StructStructureType
      binja_fn_type = self._construct_binja_type(ty.target_type, as_specifier=True)
      binja_ptr_type = bn.Type.pointer(bv.arch, binja_fn_type, ref_type=bn.ReferenceType.PointerReferenceType)
      mp_struct.insert(0, binja_ptr_type, 'member')
      binja_type = bn.Type.structure_type(mp_struct)
    elif isinstance(ty, StringType):
      if ty.is_null_terminated is False:
        assert(ty.byte_size is not None)
        binja_element_type = bn.Type.int(ty.char_size, sign=False)
        count = int(ty.byte_size / ty.char_size)
        if count > 65535:
          count = 0
        if not isinstance(count, int):
          raise Exception(f'invalid count for array. ({ty.byte_size=}) ({ty.char_size=})')
        binja_type = bn.Type.array(binja_element_type, count)
      else:
        raise NotImplementedError('null terminated string')
    else:
      raise NotImplementedError(type(ty))

    return binja_type

  def _translate_parameter(self, param: Parameter, binja_function: bn.Function, local_vars: LocationIndex):
    sym = binja_function.symbol
    assert(sym is not None)

    if len(param.locations) == 0:
      self._log.debug(f'In {sym.short_name}(): parameter ("{param.name}") has no locations')
      return

    if param.type is None:
      self._log.debug(f'In {sym.short_name}(): parameter ("{param.name}") has no type')
      return

    binja_type = self._construct_binja_type(param.type, as_specifier=True)

    resolved = False
    for loc in param.locations:
      result = local_vars.update_variable(loc, binja_type, param.local_name)
      if result.status == VariableUpdateStatus.UPDATED:
        resolved = True

    if resolved:
      self.statistics['num_parameters_resolved'] += 1
    else:
      if param.function.is_inlined:
        return

      for loc in param.locations:
        assert(loc.type == LocationType.STATIC_LOCAL)
        if loc.begin == 0 or binja_function in self._binary_view.get_functions_containing(loc.begin):
          self.statistics['num_parameters_unresolved'] += 1
          self._log.debug(
            f'In {sym.short_name}(): '
            f'unable to resolve parameter ("{param.name}", # locs = {len(param.locations)})')
          for loc in param.locations:
            self._log.debug(f'  --> {loc}')
          break

  def _translate_local_variable(self, var: LocalVariable, binja_function: bn.Function, local_vars: LocationIndex):
    sym = binja_function.symbol
    assert(sym is not None)

    if len(var.locations) == 0:
      self._log.debug(f'In {sym.short_name}(): local variable has no locations ("{var.name}")')
      return

    results: List[VariableUpdate] = []

    if var.type is None:
      self._log.debug(f'In {sym.short_name}(): local variable has no type ("{var.name}")')
      return

    binja_type = self._construct_binja_type(var.type, as_specifier=True)
    for loc in var.locations:
      assert(len(loc.expr) != 1 or not isinstance(loc.expr[0], int))
      r = local_vars.update_variable(loc, binja_type, var.local_name)
      results.append(r)

    if any(map(lambda r: r.status == VariableUpdateStatus.CONFLICT, results)):
      self._log.debug(f'In {sym.short_name}(): local variable has conflicts ("{var.name}")')
      if var.function.is_inlined is False:
        self.statistics['num_variable_conflicts'] += 1
        var.function.set_attribute('has_variable_conflict', True)

    if any(map(lambda r: r.status == VariableUpdateStatus.UPDATED, results)):
      self.statistics['num_variables_resolved'] += 1
      for r in results:
        if r.status == VariableUpdateStatus.UPDATED:
          assert(r.storage_type is not None)
          assert(r.storage_id is not None)
          assert(isinstance(r.storage_type, int))
          assert(isinstance(r.storage_id, int))
          var.storage.append(VariableStorage(r.storage_type, r.storage_id))
    else:
      self._log.debug(f'In {sym.short_name}(): unable to resolve variable ("{var.name}")')
      for loc in var.locations:
        self._log.debug(f'  --> {loc}')
      self.statistics['num_variables_unresolved'] += 1
    return

  def _rename_symbol(self, symbol: bn.CoreSymbol, new_name: str):
    new_symbol = bn.Symbol(symbol.type, symbol.address, new_name, new_name, symbol.raw_name)
    self._binary_view.define_user_symbol(new_symbol)

  def _rename_variable(self, var: Variable, binja_var: bn.Variable):
    pass

  def _translate_function_type(self, function: Function, binja_function: bn.Function):
    if binja_function.mlil is None:
      if binja_function.analysis_skipped:
        binja_function.analysis_skipped = False
        self._binary_view.update_analysis_and_wait()
        if binja_function.mlil is None:
          if binja_function.analysis_skipped:
            self._log.warning(
              f'Function skipped 2: {binja_function.symbol.short_name}'
              f' (reason = {binja_function.analysis_skip_reason.name}, {binja_function.analysis_performance_info})')
            return False
          assert binja_function.mlil is not None
      else:
        self._binary_view.update_analysis_and_wait()
        if binja_function.mlil is None:
          if binja_function.analysis_skipped:
            self._log.warning(
              f'Function skipped 3: {binja_function.symbol.short_name}'
              f' (reason = {binja_function.analysis_skip_reason.name}, {binja_function.analysis_performance_info})')
            return False
          assert binja_function.mlil is not None
        else:
          assert binja_function.mlil is not None, 'No MLIL, update did not fix, and analysis not skipped.'

    try:
      local_vars = LocationIndex(binja_function, None, self._log)
      function_type = self._create_function_type(function, binja_function, local_vars)
      if function_type is not None:
        binja_function.function_type = function_type
    except Exception:
      self._log.warning('while creating function type', exc_info=sys.exc_info())

  def _create_function_type(
    self,
    function: Function,
    binja_function: bn.Function,
    local_vars: LocationIndex
  ) -> Optional[bn.FunctionType]:
    if function.return_value is not None:
      return_type = self._construct_binja_type(function.return_value.type, as_specifier=True)
    else:
      return_type = bn.Type.void()

    parameters = []
    is_variadic = False
    for p in function.parameters:
      if isinstance(p.type, VariadicType):
        is_variadic = True
        break

      binja_type = self._construct_binja_type(p.type, as_specifier=True)
      parameters.append(bn.FunctionParameter(binja_type, p.local_name))

    return bn.Type.function(
      return_type,
      parameters,
      calling_convention=binja_function.function_type.calling_convention,
      variable_arguments=is_variadic,
      stack_adjust=binja_function.function_type.stack_adjustment)

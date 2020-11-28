# Copyright(c) 2020 Vector 35 Inc
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
from uuid import UUID, uuid4
from typing import List, Optional, Iterable, Tuple, Union, Any
from itertools import chain, tee
from collections import defaultdict
from threading import Thread
from .model import Module, Component, TouchFlags, Observer
from .model.elements import (
  Element,
  Variable,
  Constant,
  Location, LocationType,
  Function, LocalVariable, Parameter, ExprOp,
  ImportedModule, ImportedFunction, ImportedVariable,
  Type, ScalarType, CompositeType
)
from binaryninja import BinaryDataNotification
import binaryninja as bn
from .io.dwarf_import import import_ELF_DWARF_into_module
from copy import copy


def partition(items, predicate=bool):
  a, b = tee((predicate(item), item) for item in items)
  return ((item for pred, item in a if pred), (item for pred, item in b if not pred))


class VariableSet(object):
  def __init__(self, binja_function: bn.Function, logger):
    self._function = binja_function
    self._log = logger
    self._binary_view = self._function.view
    self._arch = self._binary_view.arch
    self._regs = {name.replace('%', ''): reg for name, reg in self._arch.regs.items()}
    self._variables: Mapping[bn.Variable, str] = dict()
    self._index = 900000
    self._addresses = list(map(lambda i: i[1], self._function.instructions))
    self._mlil_insns = list(self._function.mlil.instructions)
    self._hlil_insns = None

  def __iter__(self):
    return iter(self._variables.keys())

  @property
  def hlil_insns(self):
    if self._hlil_insns is None:
      try:
        self._hlil_insns = list(self._function.hlil.instructions)
      except RecursionError:
        self._hlil_insns = []
    return self._hlil_insns

  def add(self, name: str, loc: Location, binja_type = None, overwrite: bool = False) -> Optional[bn.Variable]:
    v = self._resolve_location(name, loc, binja_type)
    if v is not None:
      if v not in self._variables:
        self._variables[v] = name
        return v, False

      if self._variables[v] != name:
        # create a new stack variable.
        if v.source_type == bn.VariableSourceType.RegisterVariableSourceType:
          pass
        elif v.source_type == bn.VariableSourceType.StackVariableSourceType:
          nv = self._make_stack_variable(v.storage, binja_type=v.type)
          nv.index = self._index
          self._index += 1
          self._variables[v] = name
          return v, False
      return v, True

    return None, None

  def _resolve_location(self, name: str, loc: Location, binja_type = None) -> Optional[bn.Variable]:
    """Resolves a location expression to a local BN Variable, if possible.
    """
    if loc.type != LocationType.STATIC_LOCAL:
      print(loc)
    assert(loc.type == LocationType.STATIC_LOCAL)
    if len(loc.expr) == 1:
      item = loc.expr[0]
      if isinstance(item, str):
        # A single register
        return self._find_register_in_range(loc.begin, loc.end, item)
      elif isinstance(item, int):
        self._log.debug(f'Location for local ("{name}") is a global address (0x{item:x}) 0x{loc.begin:x}-0x{loc.end:x}.')
        return None
        # A static memory address
        datavar = self._binary_view.get_data_var_at(item)
        if datavar is not None:
          return datavar
        self._binary_view.define_user_data_var(item, binja_type)
        return self._binary_view.get_data_var_at(item)
    elif len(loc.expr) == 3:
      if loc.expr[2] == ExprOp.ADD:
        offset = None
        if loc.expr[0] == ExprOp.CFA:
          offset = loc.expr[1] - self._arch.address_size
        elif isinstance(loc.expr[0], str):
          reg_val = self._reg_is_stack_offset(loc.expr[0], loc.begin, loc.end)
          if reg_val != None and reg_val.type == bn.RegisterValueType.StackFrameOffset:
            offset = reg_val.offset + loc.expr[1]
        if offset is not None:
          predicate = None if loc.begin == 0 else lambda addr: loc.begin <= addr and addr <= loc.end
          addresses = filter(predicate, self._addresses)
          for addr in addresses:
            v = self._function.get_stack_var_at_frame_offset(offset, addr)
            if v is not None:
              return v
          self._log.warning(f'Unable to find a stack variable ({name}) here {loc}')
          return None
        else:
          self._log.debug(f'TODO: Find a matching SET insn {loc.begin:x}-{loc.end:x}: {loc.expr}')
          return None
      else:
        if loc.expr[2] == ExprOp.VAR_FIELD:
          self._log.debug(f'TODO: Support some cases of VARFIELD {loc.expr}')
          return None
        self._log.warning(f'Unexpected location expression {loc.expr}')
        return None
      self._log.error(str(loc))
      assert(False)
    return None

  def _reg_is_stack_offset(self, reg_name, begin, end):
    for insn in self._mlil_insns:
      if begin == 0 or (begin <= insn.address and insn.address <= end):
        # Get the base register.
        reg_val = self._function.get_reg_value_at(insn.address, reg_name)
        if reg_val.type == bn.RegisterValueType.StackFrameOffset:
          return reg_val
    return None

  def _find_register_in_range(self, begin: int, end: int, reg_name: str) -> Optional[bn.Variable]:
    if begin == self._function.start or begin == 0:
      return self._make_variable(reg_name)

    # Find the register using the full-width register name.
    r = self._regs.get(reg_name)
    if r is None:
      return None
    reg_name = r.full_width_reg

    # TODO: Use interval tree query for looking up instructions?
    for insn in self._mlil_insns:
      if begin <= insn.address and insn.address <= end:
        for v in chain(insn.vars_read, insn.vars_written):
          # if reg_name == 'rdi':
          #     print(hex(insn.address), insn)
          if v.source_type == bn.VariableSourceType.RegisterVariableSourceType:
            if self._arch.get_reg_name(v.storage) == reg_name:
              return v

    for insn in self.hlil_insns:
      if begin <= insn.address and insn.address <= end:
        for v in filter(lambda opnd: isinstance(opnd, bn.Variable), insn.postfix_operands):
          if v.source_type == bn.VariableSourceType.RegisterVariableSourceType:
            if self._arch.get_reg_name(v.storage) == reg_name:
              return v
    return None

  def _make_variable(self, reg_name: str) -> Optional[bn.Variable]:
    full_width_reg_name = self._regs[reg_name].full_width_reg
    return bn.Variable(
        self._function,
        bn.VariableSourceType.RegisterVariableSourceType,
        index=0,
        storage=self._arch.get_reg_index(full_width_reg_name),
        name=reg_name,
        var_type=bn.Type.int(self._arch.address_size))

  def _make_stack_variable(self, offset: int, binja_type = None) -> Optional[bn.Variable]:
    var_type = binja_type if binja_type else bn.Type.int(self._arch.address_size)
    return bn.Variable(
        self._function,
        bn.VariableSourceType.StackVariableSourceType,
        index=13371337,
        storage=offset,
        name=f'var_{offset}',
        var_type=var_type)

  def propagate_variable_names(self):
    # Using BFS, propagate along SET_VAR operations.
    fixed_names = set(self._variables.keys())
    queue = list(fixed_names)
    while queue:
      v = queue.pop(0)
      # Get uses and definitions.
      # If the encountered variables are not in the fixed set, rename them.
      if isinstance(v, bn.DataVariable):
        continue
      if v.source_type == bn.VariableSourceType.StackVariableSourceType and v.type.type_class == bn.TypeClass.ArrayTypeClass:
        for insn in self._mlil_insns:
          if insn.operation == bn.MediumLevelILOperation.MLIL_SET_VAR and insn.src.operation == bn.MediumLevelILOperation.MLIL_ADDRESS_OF:
            if insn.src.src == v:
              use_insn: bn.MediumLevelILInstruction = insn
              d = use_insn.dest
              if d in fixed_names:
                continue
              self._rename_binja_var(d, v.name)
              d.name = v.name
              fixed_names.add(d)
              queue.append(d)
      else:
        for use_insn in self._function.mlil.get_var_uses(v):
          if use_insn.operation == bn.MediumLevelILOperation.MLIL_SET_VAR and use_insn.src.operation == bn.MediumLevelILOperation.MLIL_VAR:
            d = use_insn.dest
            if d in fixed_names:
              continue
            self._rename_binja_var(d, v.name)
            d.name = v.name
            fixed_names.add(d)
            queue.append(d)
        for def_insn in self._function.mlil.get_var_definitions(v):
          if (def_insn.operation == bn.MediumLevelILOperation.MLIL_SET_VAR
              and (def_insn.src.operation == bn.MediumLevelILOperation.MLIL_VAR
                   or (def_insn.src.operation == bn.MediumLevelILOperation.MLIL_VAR_FIELD and def_insn.src.src.source_type == bn.VariableSourceType.RegisterVariableSourceType
                       ))):
            u = def_insn.src.src
            if u in fixed_names:
              continue
            self._rename_binja_var(u, v.name)
            u.name = v.name
            fixed_names.add(u)
            queue.append(u)

  def _rename_binja_var(self, binja_var: bn.Variable, new_name: str):
    if new_name is None:
      return
    if binja_var.type is None:
      self._log.error(f'variable "{new_name}" has no type')
      return
    if binja_var.source_type == bn.VariableSourceType.StackVariableSourceType:
      # self._log.debug(f'>>>> creating stack var "{new_name}"')
      self._function.create_user_stack_var(binja_var.storage, binja_var.type, new_name)
    else:
      self._function.create_user_var(binja_var, binja_var.type, new_name)


class BinjaBridge(Observer, BinaryDataNotification):
  """Two-way synchronization between Binja Core and the Sidekick Plugin.

  The bridge is a Module observer which forwards changes to the Binja core.
  Similarly, the bridge is a BinaryView observer which forwards changes
  from the core to the Module.

  The Sidekick models elements have a version number which is used
  for synchronizing.  The bridge maintains the table of the version
  number of each element which has been forwarded to Binja.  Similarly,
  the version number is updated when changes from the Binja side
  result in updates to the Sidekick model elements.
  """

  def __init__(self, mapped_model, parameters_mode='inferred'):
    Observer.__init__(self, set(), dwell_time=1)
    self._log = logging.getLogger('Bridge')
    self._mapped_model = mapped_model
    self._module = mapped_model.module
    self._mapping = mapped_model.mapping
    self._parameters_mode = parameters_mode
    self._version_table: Mapping[UUID, int] = dict()
    self._s2b_types: Mapping[UUID, Union[str, Tuple[str]]] = dict()
    self._b2s_types: Mapping[Union[str, Tuple[str]], UUID] = dict()
    self._base_types: Mapping[str, bn.Type] = dict()
    self._builtin_types = set()
    self._typelib_defined_types = set()
    self._module.add_observer(self)
    self._binary_view: bn.BinaryView = mapped_model.binary_view
    self._binary_view.register_notification(self)
    self.statistics = defaultdict(int)
    self._batch_mode = False

  def import_debug_info(self):
    self._log.debug('Running...')
    # If the mapped model has debug information available,
    # or if the binary has debug information, import it.
    # Otherwise, wait for analysis to complete and then
    # create a global component that contains all of the
    # functions.
    debug_info = self._mapped_model.get_debug_info()
    if debug_info is None:
      self._log.debug('No debug info; creating a global component')
      # self._mapped_model.binary_view.update_analysis_and_wait()
      self._module.add_component(self._create_global_component())
    else:
      self._log.debug('Debug info detected; creating components from debug info')
      # self._mapped_model.binary_view.update_analysis_and_wait()

      # For non-interactive batch import, do not respond to Module events.
      self._batch_mode = True
      import_ELF_DWARF_into_module(debug_info, self._module, debug_root=self._mapped_model.debug_root)  # {"globals_filter": lambda n: n == 'main'})
      self._batch_mode = False

      # Gather all of the defined types across all of the components.
      self.apply_all_types()

      # With the types in place, now translate the components.
      for c in self._module.traverse_components():
        self._translate_component(c)
        # self._binary_view.update_analysis_and_wait()

  def apply_all_types(self):
    self._typelib_defined_types = set(self._binary_view.types.keys())
    types = [ty for c in self._module.traverse_components() for ty in filter(self._mapping.is_newer, c.types)]
    # Translate these types in a pseudo-topological order.
    for ty in sorted(types, key=lambda ty: len(ty.members)):
      self._translate_type(ty)

  def _create_model_function(self, binja_function: bn.Function) -> Function:
    function = Function(name=binja_function.name, start=binja_function.start)
    function.no_return = not binja_function.can_return
    return self._mapping.commit(function)

  def on_idle(self, flags):
    # self.add_children(self.invisibleRootItem(), self._module.submodules)
    pass

  def on_submodules_added(self, submodules: List[Module]):
    if self._batch_mode:
      return
    for m in submodules:
      for c in m.traverse_components():
        self._translate_component(c)
        self._binary_view.update_analysis()
    self._binary_view.commit_undo_actions()

  def on_components_added(self, components):
    if self._batch_mode:
      return
    for c in components:
      self._translate_component(c)
      self._binary_view.update_analysis()
    self._binary_view.commit_undo_actions()

  def on_elements_added(self, elements: List[Element]):
    if isinstance(elements[0].owner, Component):
      c = elements[0].owner
      self._translate_component_elements(c, elements)
    elif isinstance(elements[0].owner, Function):
      fn = elements[0].function
      self._translate_function_elements(fn, elements)
    self._binary_view.update_analysis()
    self._binary_view.commit_undo_actions()

  def on_submodule_renamed(self, submodule, old_name):
    pass

  def on_component_renamed(self, component, old_name):
    pass

  def on_element_renamed(self, element, old_name):
    if isinstance(element, Function):
      binja_function = self._binary_view.get_function_at(element.start)
      if binja_function:
        self._rename_function(element, binja_function)
    elif isinstance(element, Variable):
      binja_variable = self._binary_view.get_data_var_at(element.start)
      if binja_variable:
        self._rename_variable(element, binja_variable)
    else:
      assert(False)

  def _translate_component(self, component: Component):
    self._log.debug(f'Translating component ("{component.name}")')
    num_created = 0
    for start in component.function_starts():
      binja_function = self._binary_view.get_function_at(start)
      if binja_function is None:
        self._binary_view.create_user_function(start)
        num_created += 1
    self._translate_component_elements(component, component.members)
    self._binary_view.commit_undo_actions()

  def _translate_component_elements(self, component: Component, elements: Iterable[Element]):
    for el in filter(self._mapping.is_newer, elements):
      if isinstance(el, Type):
        self._translate_type(el)
      elif isinstance(el, Variable):
        self._translate_variable(el)
      elif isinstance(el, Function):
        self._translate_function(el)
      elif isinstance(el, Constant):
        self._translate_constant(el)
      elif isinstance(el, ImportedModule):
        self._translate_imported_module(el)
      else:
        self._log.warning(f'untranslated element: {type(el)}')

  def _translate_constant(self, const: Constant):
    pass

  def _translate_imported_module(self, imported_module: ImportedModule):
    pass

  def _translate_variable(self, var: Variable):
    if var.start is None:
      self.statistics['num_globals_unresolved'] += 1
      self._log.debug(f'global variable "{var.name}" has no address')
      return
    else:
      self.statistics['num_globals_resolved'] += 1

    binja_type = self._construct_binja_type(var.type, as_specifier=True)

    # Redefine or create the variable, as needed.
    binja_var: bn.DataVariable = self._binary_view.get_data_var_at(var.start)
    if binja_var is None or binja_var.type != binja_type:
      self._binary_view.define_user_data_var(var.start, binja_type)
      binja_var: bn.DataVariable = self._binary_view.get_data_var_at(var.start)

    if binja_var is None:
      self._log.error(f'unable to define variable "{var.name}" at 0x{var.start:x}')
      return

    # Set the name of the symbol.
    symbol: bn.Symbol = self._binary_view.get_symbol_at(var.start)
    if symbol is None or symbol.short_name != var.name:
      name = '::'.join(var.name) if isinstance(var.name, tuple) else var.name
      self._binary_view.define_user_symbol(bn.Symbol(bn.SymbolType.DataSymbol, var.start, name))
      # TODO: create a version and include in the mapping

  def _translate_function(self, fn: Function):
    """
    Alignment between the function types:
        1. number of parameters
        2. alignment of parameters
    Alignment between the variables and the function parameters:
        1. is variable a detected parameter?
    """
    if not self._mapping.is_newer(fn):
      return

    # Update the version table.
    self._version_table[fn.uuid] = fn.version
    self._log.debug(f'Translating function ("{fn.name}", {fn.version})')

    # Ensure that the function exists in the BinaryView.
    binja_function: bn.Function = self._binary_view.get_function_at(fn.start)
    if binja_function is None:
      self._binary_view.create_user_function(fn.start)
      print('Updating analysis and waiting...')
    #   self._binary_view.update_analysis_and_wait()
      binja_function = self._binary_view.get_function_at(fn.start)
      if binja_function is None:
        self._log.warning(f'Unable to create a function at {fn.start:x}')
        return

    # Set the no-return attribute.
    binja_function.can_return = not fn.no_return
    prior_ftype = binja_function.function_type

    # Propagate the function name.
    binja_symbol: bn.Symbol = binja_function.symbol
    if fn.name != None and binja_symbol.full_name != fn.name:
      self._rename_symbol(binja_symbol, fn.name)

    locals = VariableSet(binja_function, self._log)

    # Update the function type.
    if self._parameters_mode == 'inferred':
      for p in fn.parameters:
        self._translate_parameter(p, binja_function, locals)

    # Translate the local variables.
    for v in fn.variables:
      self._translate_local_variable(v, binja_function, locals)

    # Translate the inlined functions.
    for inlined_function in fn.inlined_functions:
      self._translate_inlined_function(inlined_function, binja_function, locals)

    # Propagate local variable names.
    locals.propagate_variable_names()

    if self._parameters_mode == 'declared':
      self._translate_function_type(fn, binja_function)

    elif self._parameters_mode == 'inferred':
      if len(binja_function.function_type.parameters) != len(fn.parameters):
        # self._binary_view.update_analysis_and_wait()

        # Find the first parameter (from the right) whose name has changed.
        current_ftype = binja_function.function_type
        last = None
        for i in range(len(current_ftype.parameters)-1, -1, -1):
          if i < len(prior_ftype.parameters):
            if current_ftype.parameters[i].name != prior_ftype.parameters[i].name:
              last = i
              break

        if last is not None and last+1 < len(current_ftype.parameters):
          # i is the index of the new last argument
          new_ftype = bn.Type.function(
              current_ftype.return_value,
              current_ftype.parameters[:last+1],
              current_ftype.calling_convention,
              current_ftype.has_variable_arguments,
              current_ftype.stack_adjustment)
          binja_function.function_type = new_ftype

  def _translate_inlined_function(self, inlined_function: Function, binja_function: bn.Function, locals: VariableSet):
    # self._log.debug(f'        /{inlined_function.name}/')
    for p in inlined_function.parameters:
      if p.name and p.name != 'this':
        self._translate_parameter(p, binja_function, locals)
    self._translate_function_elements(inlined_function, (), binja_function, locals)

  def _translate_function_elements(self, fn: Function, elements: Iterable[Element], binja_function: bn.Function, locals: VariableSet):
    is_inlined = isinstance(fn.owner, Function)
    # Ensure that the function exists in the BinaryView.
    for el in elements:
      if isinstance(el, LocalVariable):
        self._translate_local_variable(el, binja_function, locals)
      elif isinstance(el, Parameter):
        self._translate_parameter(el, binja_function, locals)
    for inlined_function in fn.inlined_functions:
      self._translate_inlined_function(inlined_function, binja_function, locals)

  def _translate_type(self, ty: Type):
    """Translation of named types - those which are registered with a name.
    """
    # Don't redefine the same type (by uuid).
    if ty.uuid in self._s2b_types:
      return
    # Only define types with names.
    if ty.name is None:
      return
    # Don't redefine types imported from type libaries.
    if ty.name in self._typelib_defined_types:
      return
    # Don't define composite with no members... what's the point
    if ty.composite_type is not None and len(ty.members) == 0:
      return

    # # Only define types with actual definitions.
    # if ty.composite_type is not None and len(ty.members) == 0:
    #     return
    # If the same type name is encountered multiple times,
    # only translate the type if it is a superset of the previous definition.
    if ty.name in self._b2s_types:
      if not self.is_refinement_of(ty, self._b2s_types[ty.name]):
        return

    # Construct the binja type object.
    binja_type = self._construct_binja_type(ty)

    # Record the 2-way mapping.
    self._s2b_types[ty.uuid] = binja_type
    self._b2s_types[ty.name] = ty

    #
    if binja_type.type_class == bn.TypeClass.NamedTypeReferenceClass:
      if ty.element is None:
        assert(binja_type.named_type_reference.name == ty.name)
      else:
        # Register a typedef.
        aliased_type = self._construct_binja_type(ty.element, as_specifier=True)
        assert(aliased_type.type_class != bn.TypeClass.NamedTypeReferenceClass or aliased_type.named_type_reference.name != ty.name)

        # Is this already defined and does it have the same definition?
        # If so, then there is nothing to do here.  If not, then we've got multiple
        # definitions for the alias -- which is a problem.
        if ty.name in self._binary_view.types:
          existing_type = self._binary_view.types[ty.name]
          # if aliased_type.type_class == existing_type.type_class:
          #     return

        self._log.debug(f'(ntr) defining typedef {ty.name} as {aliased_type} ({aliased_type.type_class.name})')
        assert(ty.name not in self._binary_view.types)
        self._binary_view.define_user_type(ty.name, aliased_type)
      return

    # Don't register types that are recognized as built-ins.
    if ty.name in self._builtin_types:
      self._log.debug(f'built-in type {ty.name} as {binja_type} ({binja_type.type_class.name})')
      return

    # Register the type with the binary view.
    assert(binja_type.type_class != bn.TypeClass.NamedTypeReferenceClass)
    self._log.debug(f'defining user type {ty.name} as {binja_type} ({binja_type.type_class.name})')
    if ty.name in self._binary_view.types:
      print(f'defining user type {ty.name} as {binja_type} ({binja_type.type_class.name})')
      print(f'\tpreviously {self._binary_view.types[ty.name]}')
    # assert(ty.name not in self._binary_view.types)
    self._binary_view.define_user_type(ty.name, binja_type)

  def is_refinement_of(self, a, b) -> bool:
    if a.name != b.name:
      return False
    if len(b.members) == 0 and len(a.members) > 0:
      return True
    return False

  def _construct_binja_type(self, ty: Type, as_specifier: bool = False) -> bn.Type:
    assert(not isinstance(ty, str))
    if ty.uuid in self._s2b_types:
      if as_specifier and ty.name is not None:
        ntrc = bn.NamedTypeReferenceClass.UnknownNamedTypeClass
        if ty.composite_type is not None:
          if ty.composite_type == CompositeType.CLASS_TYPE:
            ntrc = bn.NamedTypeReferenceClass.ClassNamedTypeClass
          elif ty.composite_type == CompositeType.STRUCT_TYPE:
            ntrc = bn.NamedTypeReferenceClass.StructNamedTypeClass
          elif ty.composite_type == CompositeType.UNION_TYPE:
            ntrc = bn.NamedTypeReferenceClass.UnionNamedTypeClass
          elif ty.composite_type == CompositeType.ENUM_TYPE:
            ntrc = bn.NamedTypeReferenceClass.EnumNamedTypeClass
        binja_type = bn.Type.named_type(bn.NamedTypeReference(name=ty.name, type_id=self._generate_typeid(ty.name), type_class=ntrc))
      else:
        return self._s2b_types[ty.uuid]

    bv = self._binary_view
    if ty.scalar_type:
      if ty.scalar_type == ScalarType.BASE_TYPE:
        if ty.name in self._base_types:
          binja_type = self._base_types[ty.name]
        else:
          try:
            # If this is a parseable type, do that.
            binja_type, _ = bv.parse_type_string(ty.name)
            self._base_types[ty.name] = binja_type
            self._builtin_types.add(ty.name)
          except:
            # Otherwise, create a named type reference.
            binja_type = bn.Type.named_type(bn.NamedTypeReference(name=ty.name, type_id=self._generate_typeid(ty.name)))
            self._base_types[ty.name] = binja_type
      elif ty.scalar_type == ScalarType.POINTER_TYPE:
        target_type = self._construct_binja_type(ty.element, as_specifier=as_specifier)
        binja_type = bn.Type.pointer(bv.arch, target_type, ref_type=bn.ReferenceType.PointerReferenceType)
      elif ty.scalar_type == ScalarType.REFERENCE_TYPE:
        target_type = self._construct_binja_type(ty.element, as_specifier=as_specifier)
        binja_type = bn.Type.pointer(bv.arch, target_type, ref_type=bn.ReferenceType.ReferenceReferenceType)
      elif ty.scalar_type == ScalarType.RVALUE_REFERENCE_TYPE:
        target_type = self._construct_binja_type(ty.element, as_specifier=as_specifier)
        binja_type = bn.Type.pointer(bv.arch, target_type, ref_type=bn.ReferenceType.RValueReferenceType)
      elif ty.scalar_type == ScalarType.ARRAY_TYPE:
        element_type = self._construct_binja_type(ty.element, as_specifier=as_specifier)
        count = 0 if ty.array_count is None else ty.array_count
        if count > 65535:
          count = 0
        binja_type = bn.Type.array(element_type, count)
    elif ty.composite_type:
      if as_specifier and ty.name is not None:
        ntrc = bn.NamedTypeReferenceClass.UnknownNamedTypeClass
        if ty.composite_type == CompositeType.CLASS_TYPE:
          ntrc = bn.NamedTypeReferenceClass.ClassNamedTypeClass
        elif ty.composite_type == CompositeType.STRUCT_TYPE:
          ntrc = bn.NamedTypeReferenceClass.StructNamedTypeClass
        elif ty.composite_type == CompositeType.UNION_TYPE:
          ntrc = bn.NamedTypeReferenceClass.UnionNamedTypeClass
        elif ty.composite_type == CompositeType.ENUM_TYPE:
          ntrc = bn.NamedTypeReferenceClass.EnumNamedTypeClass
        binja_type = bn.Type.named_type(bn.NamedTypeReference(name=ty.name, type_id=self._generate_typeid(ty.name), type_class=ntrc))
      else:
        if ty.composite_type in [CompositeType.CLASS_TYPE, CompositeType.STRUCT_TYPE]:
          struct = bn.Structure()
          struct.type = bn.StructureType.StructStructureType if ty.composite_type == CompositeType.STRUCT_TYPE else bn.StructureType.ClassStructureType
          if ty.byte_size is not None:
            struct.width = ty.byte_size
          for m in ty.members:
            member_type = self._construct_binja_type(m.element, as_specifier=True)
            member_name = m.name if m.name is not None else ''
            if m.offset is not None:
              struct.insert(m.offset, member_type, member_name)
          binja_type = bn.Type.structure_type(struct)
        elif ty.composite_type == CompositeType.UNION_TYPE:
          union = bn.Structure()
          union.type = bn.StructureType.UnionStructureType
          if ty.byte_size is not None:
            union.width = ty.byte_size
          for m in ty.members:
            member_type = self._construct_binja_type(m.element, as_specifier=as_specifier)
            member_name = m.name if m.name is not None else ''
            if m.offset is not None:
              union.insert(m.offset, member_type, member_name)
          binja_type = bn.Type.structure_type(union)
        elif ty.composite_type == CompositeType.ENUM_TYPE:
          e = bn.Enumeration()
          for m in ty.members:
            e.append(m.name, m.offset)
          binja_type = bn.Type.enumeration_type(bv.arch, e, ty.byte_size)
        elif ty.composite_type == CompositeType.FUNCTION_TYPE:
          has_variable_args = False
          ret = self._construct_binja_type(ty.element, as_specifier=True)
          params = []
          for param in ty.members:
            if param.element == Type.variadic():
              has_variable_args = True
            else:
              params.append(self._construct_binja_type(param.element, as_specifier=True))
          binja_type = bn.Type.function(ret, params, variable_arguments=has_variable_args)
        elif ty.composite_type == CompositeType.PTR_TO_MEMBER_TYPE:
          binja_type = self._construct_binja_type(ty.members[1], as_specifier=True)
    elif ty.name is not None:
      ntrc = bn.NamedTypeReferenceClass.TypedefNamedTypeClass
      binja_type = bn.Type.named_type(bn.NamedTypeReference(name=ty.name, type_id=self._generate_typeid(ty.name), type_class=ntrc))
    else:
      if ty.element is None:
        print(ty.__dict__)
      assert(ty.element is not None)
      binja_type = self._construct_binja_type(ty.element, as_specifier=as_specifier).mutable_copy()
      if ty.is_constant:
        binja_type.const = True
      if ty.is_volatile:
        binja_type.volatile = True

    return binja_type

  def _generate_typeid(self, name: Union[str, Tuple[str]]) -> str:
    typeid = self._binary_view.get_type_id(name)
    if typeid is not None:
      return typeid

    self._binary_view.define_user_type(name, bn.Type.void())
    typeid = self._binary_view.get_type_id(name)
    assert(typeid is not None)
    if typeid is not None:
      return typeid

  def _translate_parameter(self, param: Parameter, binja_function: bn.Function, locals: VariableSet):
    num_resolved = 0
    for loc in param.locations:
      # Resolve the location to a MLIL variable.
      binja_var, preexists = locals.add(param.name, loc)
      if binja_var is None:
        continue
      if preexists:
        continue
      if isinstance(binja_var, bn.DataVariable):
        continue

      num_resolved += 1
      binja_type = self._construct_binja_type(param.type, as_specifier=True)

      # Set the name and type.
      new_name = param.name if param.name else binja_var.name
      if binja_var.source_type == bn.VariableSourceType.StackVariableSourceType:
        # self._log.debug(f'stack user var: storage {binja_var.storage}, name {new_name}')
        binja_function.create_user_stack_var(binja_var.storage, binja_type, new_name)
      else:
        # self._log.debug(str(binja_var)+' '+str(binja_type)+' '+new_name)
        binja_function.create_user_var(binja_var, binja_type, new_name)
      if binja_var.name != new_name:
        binja_var.name = new_name

    if num_resolved == 0:
      # Don't report errors translating the functions of inlined subroutines.
      if not isinstance(param.function.owner, Function):
        issues = []
        for loc in param.locations:
          assert(loc.type == LocationType.STATIC_LOCAL)
          # was the specified location actually in this subroutine?
          if loc.begin != 0 and binja_function in self._binary_view.get_functions_containing(loc.begin):
            issues.append(loc)
        if issues:
          self.statistics['num_parameters_unresolved'] += 1
          self._log.debug(f'In {binja_function.symbol.short_name}(): unable to resolve parameter ("{param.name}")')
          for loc in param.locations:
            self._log.debug(f'    (0x{loc.begin:08x}, 0x{loc.end:08x}, {loc.expr})')
        else:
          if len(param.locations) > 0:
            self.statistics['num_parameters_other'] += 1
    else:
      self.statistics['num_parameters_resolved'] += 1

  def _translate_local_variable(self, var: LocalVariable, binja_function: bn.Function, locals: VariableSet):
    num_resolved = 0
    num_preexists = 0
    for loc in var.locations:
      # Resolve the location to a MLIL variable.
      binja_var, preexists = locals.add(var.name, loc)
      if binja_var is None:
        continue
      if preexists:
        num_preexists += 1
        continue
      if isinstance(binja_var, bn.DataVariable):
        # A static (local scope) variable.
        binja_type = self._construct_binja_type(var.type, as_specifier=True)
        # Set the name of the symbol.
        symbol: bn.Symbol = self._binary_view.get_symbol_at(binja_var.address)
        if symbol is None or symbol.short_name != var.name:
          name = '::'.join(var.name) if isinstance(var.name, tuple) else var.name
          self._binary_view.define_user_symbol(bn.Symbol(bn.SymbolType.DataSymbol, binja_var.address, name))
        num_resolved += 1
        continue

      num_resolved += 1
      binja_type = self._construct_binja_type(var.type, as_specifier=True)
      # Coerce to a reference type, as needed
      if (binja_var.source_type == bn.VariableSourceType.RegisterVariableSourceType
              and var.type.composite_type is not None and var.type.byte_size is not None
              and var.type.byte_size > self._binary_view.arch.address_size
              ):
        binja_type = bn.Type.pointer(self._binary_view.arch, binja_type, ref_type=bn.ReferenceType.ReferenceReferenceType)
        self._log.debug(f'in {binja_function.symbol.short_name}, coercing to a reference: {binja_type}')

      # Then set the name and type.
      new_name = var.name if var.name is not None else binja_var.name
      if binja_var.source_type == bn.VariableSourceType.StackVariableSourceType:
        binja_function.create_user_stack_var(binja_var.storage, binja_type, new_name)
      else:
        # self._log.debug(f'Creating user variable {binja_var} with name {new_name}')
        binja_function.create_user_var(binja_var, binja_type, new_name)
      binja_var.name = var.name
      binja_var.type = binja_type

    if num_resolved == 0:
      issues = []
      for loc in var.locations:
        assert(loc.type == LocationType.STATIC_LOCAL)
        if loc.begin != 0 and binja_function in self._binary_view.get_functions_containing(loc.begin):
          issues.append(loc)
      if issues:
        self.statistics['num_variables_unresolved'] += 1
        self._log.debug(f'In {binja_function.symbol.short_name}()@{binja_function.start:x}: unable to resolve variable ("{var.name}"), # of locations already assigned = {num_preexists}')
        for loc in issues:
          self._log.debug(f'    (0x{loc.begin:08x}, 0x{loc.end:08x}, {loc.expr})')
      else:
        if len(var.locations) > 0:
          self.statistics['num_variables_other'] += 1
    else:
      self.statistics['num_variables_resolved'] += 1

  def _rename_symbol(self, symbol: bn.Symbol, new_name: str):
    new_symbol = bn.Symbol(symbol.type, symbol.address, new_name, new_name, symbol.raw_name)
    self._binary_view.define_user_symbol(new_symbol)

  def _rename_function(self, fn: Function, binja_function: bn.Function):
    pass

  def _rename_variable(self, var: Variable, binja_var: bn.Variable):
    pass

  def _translate_function_type(self, function: Function, binja_function: bn.Function):
    # Memoize
    if function.has_attribute('function_type'):
      function_type = function.get_attribute('function_type')
      if function_type != binja_function.function_type:
        binja_function.function_type = function_type
      return
    try:
      locals = VariableSet(binja_function, self._log)
      function_type = self._create_function_type(function, binja_function, locals)
      if function_type is not None:
        binja_function.function_type = function_type
    except:
      self._log.warning(f'while creating function type', exc_info=sys.exc_info())

  def _create_function_type(self, function: Function, binja_function: bn.Function, locals: VariableSet) -> Optional[bn.Type]:
    """Creates a binja function type from the sidekick function.

    Notes:
        Because we cannot rely on any existing binja function to have the
        correct number of parameters (or parameter locations), we use the
        parameter locations given by the sidekick function.
    """
    return_type = self._construct_binja_type(function.return_type, as_specifier=True)

    # Construct the binja parameters.
    parameters = []
    is_variadic = False
    for p in function.parameters:
      # (p.type == None) means unspecified variadic parameters.
      # No regular parameters can follow.
      if p.type is None:
        is_variadic = True
        break

      # Define the parameter type.
      binja_type = self._construct_binja_type(p.type, as_specifier=True)

      # Figure out the parameter location.
      binja_location: Optional[bn.Variable] = None
      if p.locations:
        # Use the first location that can be resolved.
        for loc in p.locations:
          binja_location, preexists = locals.add(p.name, loc, binja_type=binja_type)
          if isinstance(binja_location, bn.DataVariable):
            binja_location = None
          if binja_location is not None:
            break
        if binja_location is None:
          self._log.warning(f'while creating function type: parameter "{p.name}" could not be resolved to a location.')
          self._log.warning(p.locations)
      if binja_location is None:
        return None
      parameters.append(bn.FunctionParameter(binja_type, p.name, binja_location))

    return bn.Type.function(return_type, parameters,
                            calling_convention=binja_function.function_type.calling_convention,
                            variable_arguments=is_variadic,
                            stack_adjust=binja_function.function_type.stack_adjustment)

  def data_written(self, view, offset, length):
    pass

  def data_inserted(self, view, offset, length):
    pass

  def data_removed(self, view, offset, length):
    pass

  def function_added(self, view, func):
    pass

  def function_removed(self, view, func):
    pass

  def function_updated(self, view, func):
    pass

  def function_update_requested(self, view, func):
    pass

  def data_var_added(self, view, var):
    pass

  def data_var_removed(self, view, var):
    pass

  def data_var_updated(self, view, var):
    pass

  def string_found(self, view, string_type, offset, length):
    pass

  def string_removed(self, view, string_type, offset, length):
    pass

  def type_defined(self, view, name, type):
    pass

  def type_undefined(self, view, name, type):
    pass

  def materialize_from_binja(self, items: Union[Iterable[Any], Any]):
    element = self.materialize_element_from_binja(items)
    if element is not None:
      yield element
    try:
      iterator = iter(items)
    except TypeError:
      pass  # not iterable
    else:
      for item in iterator:
        yield self.materialize_element_from_binja(item)

  def materialize_element_from_binja(self, item: Any):
    if isinstance(item, bn.Function):
      binja_function: bn.Function = item
      function = Function(name=binja_function.name, start=binja_function.start)
      self._version_table[function.uuid] = function.version
      function.no_return = not binja_function.can_return
      return function
    else:
      return None

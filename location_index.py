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

from .model.locations import Location, ExprOp
from itertools import chain
from collections import defaultdict
from typing import MutableMapping, Union, List, Optional, Any, ValuesView, Tuple
from enum import Enum, auto
from dataclasses import dataclass
import binaryninja as bn


class VariableUpdateStatus(Enum):
  UPDATED = auto()
  ALREADY_UPDATED = auto()
  LOCATION_NOT_FOUND = auto()
  LOCATION_EXPRESSION_NOT_SUPPORTED = auto()
  INVALID_REGISTER = auto()
  CONFLICT = auto()


@dataclass
class VariableUpdate:
  status: VariableUpdateStatus
  storage_type: Optional[int] = None
  storage_id: Optional[int] = None


@dataclass(eq=True, frozen=True)
class StackLocation:
  offset: int


class LocalVariableFrame(object):
  def __init__(self, function: bn.Function):
    self._function = function
    self._declarations: MutableMapping[bn.CoreVariable, Tuple[str, bn.Type]] = dict()

  def __contains__(self, v: bn.CoreVariable):
    return v in self._declarations

  def declare_variable(self, v: bn.CoreVariable, name: str, ty: bn.Type):
    if v not in self._declarations:
      assert(v.__class__ == bn.CoreVariable)
      self._declarations[v] = (name, ty)
      tc = ty._to_core_struct()
      ignore_disjoint_uses = False
      bn._binaryninjacore.BNCreateUserVariable(self._function.handle, v.to_BNVariable(), tc, name, ignore_disjoint_uses)
      return True

    prior_name, prior_type = self._declarations[v]
    return prior_name == name and prior_type == ty

  def items(self):
    return self._declarations.items()


class LocationIndex(object):
  def __init__(self, function: bn.Function, frame_base: Optional[Union[Location, List[Location]]], log):
    self._function = function
    self._frame_base = frame_base
    self._log = log
    self._binary_view = self._function.view
    if self._binary_view.arch is None:
      raise Exception('unable to create a variable index for an undefined architecture (bv.arch is None)')
    self._arch = self._binary_view.arch
    self._arch_name = self._arch.name if self._arch.name else ''
    self._reg_aliases = {'armv7': {'r13': 'sp', 'r14': 'lr', 'r15': 'pc'},
                         'thumb2': {'r13': 'sp', 'r14': 'lr', 'r15': 'pc'},
                         'ppc': {'MSR': 'msr'}
                         }
    self._stack_frame_regs = {
      'x86_64': ['rbp', 'ebp'],
      'armv7': ['sp', 'r13'],
      'thyumb2': ['sp', 'r13']}.get(self._arch_name, list())
    self._map: MutableMapping[Any, MutableMapping[int, bn.CoreVariable]] = defaultdict(dict)
    self._local_variables = LocalVariableFrame(self._function)
    self._calc_frame_base()
    self._build_index()

  def _calc_frame_base(self):
    self._stack_offset_adjustment = 0
    if isinstance(self._frame_base, Location):
      expr = self._frame_base.expr
      if self._frame_base.begin == 0:
        if expr == (ExprOp.CFA,):
          self._stack_offset_adjustment = -self._arch.address_size
        elif len(expr) == 1 and isinstance(expr[0], str):
          fbreg_value = self._get_reg_value_at_first_insn(bn.RegisterName(expr[0]))
          if fbreg_value is not None:
            self._stack_offset_adjustment = -fbreg_value
          elif expr[0] in self._stack_frame_regs:
            self._stack_offset_adjustment = self._arch.address_size

  def _get_reg_value_at_first_insn(self, reg_name: bn.RegisterName) -> Optional[int]:
    mlil = self._function.mlil
    if len(mlil) > 0:
      first_addr = mlil[0].address
      value = self._function.get_reg_value_at(first_addr, reg_name)
      if isinstance(value, bn.StackFrameOffsetRegisterValue):
        return value.value
    return None

  def _build_index(self):
    mlil = self._function.mlil
    assert mlil is not None
    for insn in self._function.mlil.instructions:
      if (
        insn.operation == bn.MediumLevelILOperation.MLIL_TAILCALL
        or insn.operation == bn.MediumLevelILOperation.MLIL_TAILCALL_UNTYPED
      ):
        vars_accessed = insn.vars_read
      else:
        vars_accessed = chain(insn.vars_written, insn.vars_read)

      for v in vars_accessed:  # type: ignore
        assert(isinstance(v, bn.Variable))
        assert(isinstance(v._source_type, int))
        cv = bn.CoreVariable(_source_type=v._source_type, index=v.index, storage=v.storage)
        if v.source_type == bn.VariableSourceType.RegisterVariableSourceType:
          self._map[self._arch.get_reg_name(bn.RegisterIndex(v.storage))][insn.address] = cv
        elif v.source_type == bn.VariableSourceType.StackVariableSourceType:
          offset = v.storage + self._stack_offset_adjustment
          self._map[StackLocation(offset=offset)][insn.address] = cv
        elif v.source_type == bn.VariableSourceType.FlagVariableSourceType:
          pass

    for v in self._function.vars:
      cv = bn.CoreVariable(_source_type=v._source_type, index=v.index, storage=v.storage)
      if v.source_type == bn.VariableSourceType.RegisterVariableSourceType:
        loc = self._arch.get_reg_name(bn.RegisterIndex(v.storage))
        if loc not in self._map:
          self._map[loc][-1] = cv
      elif v.source_type == bn.VariableSourceType.StackVariableSourceType:
        offset = v.storage + self._stack_offset_adjustment
        loc = StackLocation(offset=offset)
        if loc not in self._map:
          self._map[loc][-1] = cv
      else:
        pass

  def update_variable(self, loc: Location, new_type: bn.Type, new_name: str) -> VariableUpdate:
    """Only update a variable if it has not already been updated.
    """
    # Find the location.
    expr = loc.expr
    if len(expr) == 1:
      expr = expr[0]
      if expr == ExprOp.CFA:
        expr = StackLocation(offset=0)
      else:
        if self._arch.name in self._reg_aliases:
          assert(isinstance(expr, str))
          alias = self._reg_aliases[self._arch_name].get(expr, None)
          if alias is not None:
            expr = alias
        r: bn.RegisterInfo = self._arch.regs.get(expr)  # type: ignore
        if r is None:
          arch = self._function.arch
          assert(arch is not None)
          print(f'NO SUCH REG {expr} - {arch.name}')
          return VariableUpdate(status=VariableUpdateStatus.INVALID_REGISTER)
        expr = r.full_width_reg
    elif len(expr) == 3:
      if expr[2] == ExprOp.ADD and expr[0] == ExprOp.CFA:
        assert(isinstance(expr[1], int))
        expr = StackLocation(offset=expr[1])
      elif expr[2] == ExprOp.VAR_FIELD:
        expr = expr[0]
      else:
        self._log.debug(f'Unhandled location expression for "{new_name}": {loc}')
        return VariableUpdate(status=VariableUpdateStatus.LOCATION_EXPRESSION_NOT_SUPPORTED)
    else:
      self._log.debug(f'Unhandled location expression for "{new_name}": {loc}')
      return VariableUpdate(status=VariableUpdateStatus.LOCATION_EXPRESSION_NOT_SUPPORTED)

    if expr not in self._map:
      return VariableUpdate(status=VariableUpdateStatus.LOCATION_NOT_FOUND)

    var_list: Union[ValuesView[bn.CoreVariable], List[bn.CoreVariable]]

    addr_map = self._map[expr]
    if loc.begin == 0:
      var_list = addr_map.values()
    else:
      var_list = []
      for addr in addr_map.keys():
        end_addr = addr + self._binary_view.get_instruction_length(addr) - 1
        if loc.begin <= addr and end_addr <= loc.end:
          v = addr_map[addr]
          var_list.append(v)

    if len(var_list) == 0:
      return VariableUpdate(status=VariableUpdateStatus.LOCATION_NOT_FOUND)

    # Finally, update the variable name and type.
    result: List[VariableUpdate] = []
    for cv in var_list:
      if self._local_variables.declare_variable(cv, new_name, new_type):
        result.append(VariableUpdate(status=VariableUpdateStatus.UPDATED, storage_type=cv._source_type, storage_id=cv.storage))
      else:
        result.append(VariableUpdate(status=VariableUpdateStatus.CONFLICT))

    for res in result:
      if res.status == VariableUpdateStatus.UPDATED:
        return res
    return result[-1]

  def propagate_names(self):
    """Using BFS, propagate along SET_VAR operations.
    """
    queue = list(self._local_variables.items())
    while queue:
      cv, (name, ty) = queue.pop(0)

      if (
        cv.source_type == bn.VariableSourceType.StackVariableSourceType
        and ty.type_class == bn.TypeClass.ArrayTypeClass
      ):
        for insn in self._function.mlil.instructions:
          if isinstance(insn, bn.MediumLevelILSetVar):
            if isinstance(insn.src, bn.MediumLevelILAddressOf):
              if cv == insn.src.src:
                assert(insn.dest.type)
                dest_cv = self.declare_variable(insn.dest, name, insn.dest.type)
                if dest_cv is not None:
                  queue.append((dest_cv, (name, insn.dest.type)))
      else:
        v = bn.Variable(self._function, cv.source_type, cv.index, cv.storage)
        for use_insn in self._function.mlil.get_var_uses(v):
          if isinstance(use_insn, bn.MediumLevelILSetVar):
            if isinstance(use_insn.src, bn.MediumLevelILVar):
              dest_cv = self.declare_variable(use_insn.dest, name, ty)
              if dest_cv is not None:
                queue.append((dest_cv, (name, ty)))

        for def_insn in self._function.mlil.get_var_definitions(v):
          if isinstance(def_insn, bn.MediumLevelILSetVar):
            if isinstance(def_insn.src, bn.MediumLevelILVar):
              src_cv = self.declare_variable(def_insn.src.src, name, ty)
              if src_cv is not None:
                queue.append((src_cv, (name, ty)))
            elif (
              isinstance(def_insn.src, bn.MediumLevelILVarField)
              and def_insn.src.src.source_type == bn.VariableSourceType.RegisterVariableSourceType
            ):
              src_type = def_insn.src.src.type
              assert(src_type)
              src_cv = self.declare_variable(def_insn.src.src, name, src_type)
              if src_cv is not None:
                queue.append((src_cv, (name, src_type)))

  def declare_variable(self, v: bn.Variable, name: str, ty: bn.Type):
    cv = bn.CoreVariable(v._source_type, v.index, v.storage)
    if cv not in self._local_variables:
      if self._local_variables.declare_variable(cv, name, ty):
        return cv
    return None

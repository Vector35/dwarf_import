# Copyright (c) 2020 Vector 35 Inc

from .model.locations import Location, ExprOp
from itertools import chain
from collections import defaultdict
from typing import MutableMapping, Union, List, Optional, Any
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


class LocationIndex(object):
  def __init__(self, function: bn.Function, frame_base: Optional[Union[Location, List[Location]]], log):
    self._function = function
    self._frame_base = frame_base
    self._log = log
    self._binary_view = self._function.view
    self._arch = self._binary_view.arch
    self._reg_aliases = {'armv7': {'r13': 'sp', 'r14': 'lr', 'r15': 'pc'},
                         'thumb2': {'r13': 'sp', 'r14': 'lr', 'r15': 'pc'},
                         'ppc': {'MSR': 'msr'}
                         }
    self._map: MutableMapping[Any, MutableMapping[int, bn.Variable]] = defaultdict(dict)
    self._updated_set: MutableMapping[bn.Variable, bn.Variable] = dict()
    self._calc_frame_base()
    self._build_index()

  def _calc_frame_base(self):
    self._stack_offset_adjustment = None
    if isinstance(self._frame_base, Location):
      expr = self._frame_base.expr
      if self._frame_base.begin == 0:
        if expr == (ExprOp.CFA,):
          self._stack_offset_adjustment = -self._arch.address_size
        elif len(expr) == 1 and isinstance(expr[0], str):
          # Get the value of the frame base pointer.
          fbreg_value = self._get_register_value(expr[0])
          if fbreg_value is not None:
            self._stack_offset_adjustment = -fbreg_value
          elif expr[0] in ['rbp', 'ebp']:
            # Special case: assume rbp is 8 when it can't be recovered.
            self._stack_offset_adjustment = self._arch.address_size

  def _get_register_value(self, reg_name: str) -> Optional[int]:
    mlil_start = None
    for insn in self._function.mlil.instructions:
      mlil_start = insn.address
      break
    if mlil_start is None:
      return None
    value = self._function.get_reg_value_at(mlil_start, reg_name)
    if value.type == bn.RegisterValueType.StackFrameOffset:
      return value.offset
    return None

  def _build_index(self):
    # Scan all MLIL instructions
    for insn in self._function.mlil.instructions:
      if (
          insn.operation == bn.MediumLevelILOperation.MLIL_TAILCALL
          or insn.operation == bn.MediumLevelILOperation.MLIL_TAILCALL_UNTYPED
      ):
        vars_accessed = insn.vars_read
      else:
        vars_accessed = chain(insn.vars_written, insn.vars_read)
      for v in vars_accessed:
        if v.source_type == bn.VariableSourceType.RegisterVariableSourceType:
          self._map[self._arch.get_reg_name(v.storage)][insn.address] = v
        elif v.source_type == bn.VariableSourceType.StackVariableSourceType:
          offset = v.storage
          if self._stack_offset_adjustment is not None:
            offset += self._stack_offset_adjustment
          self._map[StackLocation(offset=offset)][insn.address] = v

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
          alias = self._reg_aliases[self._arch.name].get(expr, None)
          if alias is not None:
            expr = alias
        r = self._arch.regs.get(expr)
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
        # Multiple VAR_FIELDS... then we just build each location
        # but map the separate pieces to different names.
        self._log.debug(f'Unhandled location expression for "{new_name}": {loc}')
        return VariableUpdate(status=VariableUpdateStatus.LOCATION_EXPRESSION_NOT_SUPPORTED)
    else:
      self._log.debug(f'Unhandled location expression for "{new_name}": {loc}')
      return VariableUpdate(status=VariableUpdateStatus.LOCATION_EXPRESSION_NOT_SUPPORTED)

    # Find the location in the map.
    if expr not in self._map:
      # If the location is valid for the function,
      # then just define the variable.
      if (
          (loc.begin == 0 or self._function in self._binary_view.get_functions_containing(loc.begin))
          and isinstance(expr, str)
      ):
        v = self._define_register_variable(expr, new_type, new_name)
        self._updated_set[v] = v
        self._map[expr][loc.begin] = v
        return VariableUpdate(
            status=VariableUpdateStatus.UPDATED,
            storage_type=int(v.source_type),
            storage_id=v.storage)
      return VariableUpdate(status=VariableUpdateStatus.LOCATION_NOT_FOUND)

    var_list = []
    addr_map = self._map[expr]
    if loc.begin == 0:
      var_list = addr_map.values()
    else:
      for addr in addr_map.keys():
        # DWARF will sometimes refer to the address of the last byte of
        # an instruction.  So we compute the end address for the test
        # by taking into account the instruction length.
        end_addr = addr + self._binary_view.get_instruction_length(addr) - 1
        if loc.begin <= addr and end_addr <= loc.end:
          v = addr_map[addr]
          var_list.append(v)

    if len(var_list) == 0:
      # print('NOT FOUND IN ADDRESS RANGE', self._function.name, new_name, loc, self._map)
      return VariableUpdate(status=VariableUpdateStatus.LOCATION_NOT_FOUND)

    result = []
    for v in var_list:
      if v in self._updated_set:
        v = self._updated_set[v]
        if v.type != new_type or v.name != new_name:
          result.append(VariableUpdate(status=VariableUpdateStatus.CONFLICT))
        else:
          result.append(VariableUpdate(status=VariableUpdateStatus.ALREADY_UPDATED))
      else:
        self._update_var_name_and_type(v, new_type, new_name)
        result.append(VariableUpdate(
            status=VariableUpdateStatus.UPDATED,
            storage_type=int(v.source_type),
            storage_id=v.storage))

    for r in result:
      if r.status == VariableUpdateStatus.UPDATED:
        return r
    return result[-1]

  def _update_var_name_and_type(self, var: bn.Variable, ty: bn.Type, name: str):
    if var.source_type == bn.VariableSourceType.StackVariableSourceType:
      self._function.create_user_stack_var(var.storage, ty, name)
    elif var.source_type == bn.VariableSourceType.RegisterVariableSourceType:
      self._function.create_user_var(var, ty, name)
    var.name = name
    var.type = ty
    self._updated_set[var] = var

  def _update_var_name(self, var: bn.Variable, name: str):
    if var.source_type == bn.VariableSourceType.StackVariableSourceType:
      self._function.create_user_stack_var(var.storage, var.type, name)
    elif var.source_type == bn.VariableSourceType.RegisterVariableSourceType:
      self._function.create_user_var(var, var.type, name)
    var.name = name
    self._updated_set[var] = var

  def _define_register_variable(self, reg_name: str, ty: bn.Type, var_name: str) -> bn.Variable:
    full_width_reg_name = self._arch.regs[reg_name].full_width_reg
    v = bn.Variable(
        self._function,
        bn.VariableSourceType.RegisterVariableSourceType,
        0, self._arch.get_reg_index(full_width_reg_name),
        var_name, ty)
    self._function.create_user_var(v, v.type, v.name)
    return v

  # def _make_stack_variable(self, offset: int, binja_type=None) -> Optional[bn.Variable]:
  #     if binja_type:
  #         var_type = binja_type
  #     else:
  #         var_type = bn.Type.int(self._arch.address_size)
  #         var_type.confidence = 1
  #     return bn.Variable(
  #         self._function,
  #         bn.VariableSourceType.StackVariableSourceType,
  #         index=13371337,
  #         storage=offset,
  #         name=f'var_{offset}',
  #         var_type=var_type)

  def propagate_names(self):
    # Using BFS, propagate along SET_VAR operations.
    queue = list(self._updated_set.values())
    while queue:
      v = queue.pop(0)
      # Get uses and definitions.
      # If the encountered variables are not in the fixed set, rename them.
      if isinstance(v, bn.DataVariable):
        continue

      if (
          v.source_type == bn.VariableSourceType.StackVariableSourceType
          and v.type is not None
          and v.type.type_class == bn.TypeClass.ArrayTypeClass
      ):
        # We can't call get_var_uses() because often the variable's
        # address is taken and that's not a use of the variable's value.
        # However, we still want to propagate because that is how we
        # obtain references to stack variables.
        for insn in self._function.mlil.instructions:
          # When taking the address of a variable we only want to
          # propagate the name to the variable because the destination
          # variable is actually a pointer to the element type, not
          # an array.  So, only propagate the name.
          if (
              insn.operation == bn.MediumLevelILOperation.MLIL_SET_VAR
              and insn.src.operation == bn.MediumLevelILOperation.MLIL_ADDRESS_OF
          ):
            if insn.src.src == v:
              use_insn: bn.MediumLevelILInstruction = insn
              d: bn.Variable = use_insn.dest  # type: ignore
              if d not in self._updated_set:
                self._update_var_name(d, v.name)
                queue.append(d)
        continue

      for use_insn in self._function.mlil.get_var_uses(v):
        if (
            use_insn.operation == bn.MediumLevelILOperation.MLIL_SET_VAR
            and use_insn.src.operation == bn.MediumLevelILOperation.MLIL_VAR  # type: ignore
        ):
          defined_var: bn.Variable = use_insn.dest  # type: ignore
          if defined_var not in self._updated_set:
            self._update_var_name_and_type(defined_var, v.type, v.name)
            queue.append(defined_var)

      for def_insn in self._function.mlil.get_var_definitions(v):
        if (
            def_insn.operation == bn.MediumLevelILOperation.MLIL_SET_VAR
            and (
                def_insn.src.operation == bn.MediumLevelILOperation.MLIL_VAR
                or (
                    def_insn.src.operation == bn.MediumLevelILOperation.MLIL_VAR_FIELD
                    and def_insn.src.src.source_type == bn.VariableSourceType.RegisterVariableSourceType
                )
            )
        ):
          used_var = def_insn.src.src
          if used_var not in self._updated_set:
            self._update_var_name_and_type(used_var, v.type, v.name)
            queue.append(used_var)

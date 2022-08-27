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

from elftools.dwarf.dwarf_expr import struct_parse, bytelist2string, DW_OP_name2opcode, DW_OP_opcode2name
from elftools.dwarf.descriptions import _REG_NAMES_x64, _REG_NAMES_x86
from .elftools_extras import describe_reg_name, _REG_NAMES_ARM, _REG_NAMES_MIPS, _REG_NAMES_POWERPC, _REG_NAMES_AArch64
from ..model.locations import ExprOp, LocationType
from typing import List, Optional, Union
from io import BytesIO

DW_OP_addr = 0x03
DW_OP_deref = 0x06
DW_OP_const1u = 0x08
DW_OP_const1s = 0x09
DW_OP_const2u = 0x0a
DW_OP_const2s = 0x0b
DW_OP_const4u = 0x0c
DW_OP_const4s = 0x0d
DW_OP_const8u = 0x0e
DW_OP_const8s = 0x0f
DW_OP_constu = 0x10
DW_OP_consts = 0x11
DW_OP_dup = 0x12
DW_OP_drop = 0x13
DW_OP_over = 0x14
DW_OP_pick = 0x15
DW_OP_swap = 0x16
DW_OP_rot = 0x17
DW_OP_xderef = 0x18
DW_OP_abs = 0x19
DW_OP_and = 0x1a
DW_OP_div = 0x1b
DW_OP_minus = 0x1c
DW_OP_mod = 0x1d
DW_OP_mul = 0x1e
DW_OP_neg = 0x1f
DW_OP_not = 0x20
DW_OP_or = 0x21
DW_OP_plus = 0x22
DW_OP_plus_uconst = 0x23
DW_OP_shl = 0x24
DW_OP_shr = 0x25
DW_OP_shra = 0x26
DW_OP_xor = 0x27
DW_OP_bra = 0x28
DW_OP_eq = 0x29
DW_OP_ge = 0x2a
DW_OP_gt = 0x2b
DW_OP_le = 0x2c
DW_OP_lt = 0x2d
DW_OP_ne = 0x2e
DW_OP_skip = 0x2f
DW_OP_lit0 = 0x30
DW_OP_lit31 = 0x4f
DW_OP_reg0 = 0x50
DW_OP_reg31 = 0x6f
DW_OP_breg0 = 0x70
DW_OP_breg31 = 0x8f
DW_OP_regx = 0x90
DW_OP_fbreg = 0x91
DW_OP_bregx = 0x92
DW_OP_piece = 0x93
DW_OP_deref_size = 0x94
DW_OP_xderef_size = 0x95
DW_OP_nop = 0x96
DW_OP_push_object_address = 0x97
DW_OP_call2 = 0x98
DW_OP_call4 = 0x99
DW_OP_call_ref = 0x9a
DW_OP_form_tls_address = 0x9b
DW_OP_call_frame_cfa = 0x9c
DW_OP_bit_piece = 0x9d
DW_OP_implicit_value = 0x9e
DW_OP_stack_value = 0x9f
DW_OP_implicit_pointer = 0xa0
DW_OP_addrx = 0xa1
DW_OP_constx = 0xa2
DW_OP_entry_value = 0xa3
DW_OP_const_type = 0xa4
DW_OP_regval_type = 0xa5
DW_OP_deref_type = 0xa6
DW_OP_xderef_type = 0xa7
DW_OP_convert = 0xa8
DW_OP_reinterpret = 0xa9

DW_OP_lo_user = 0xe0
DW_OP_GNU_push_tls_address = 0xe0,
DW_OP_GNU_implicit_pointer = 0xf2,
DW_OP_GNU_entry_value = 0xf3,
DW_OP_GNU_const_type = 0xf4,
DW_OP_GNU_regval_type = 0xf5,
DW_OP_GNU_deref_type = 0xf6,
DW_OP_GNU_convert = 0xf7,
DW_OP_GNU_reinterpret = 0xf9,
DW_OP_GNU_parameter_ref = 0xfa,
DW_OP_GNU_addr_index = 0xfb,
DW_OP_GNU_const_index = 0xfc,
DW_OP_hi_user = 0xff


class StaticExprEvaluator(object):
  """ A DWARF expression is a sequence of instructions encoded in a block
      of bytes. This class decodes the sequence into discrete instructions
      with their arguments and allows generic "visiting" to process them.

      Usage: subclass this class, and override the needed methods. The
      easiest way would be to just override _after_visit, which gets passed
      each decoded instruction (with its arguments) in order. Clients of
      the visitor then just execute process_expr. The subclass can keep
      its own internal information updated in _after_visit and provide
      methods to extract it. For a good example of this usage, see the
      ExprDumper class in the descriptions module.

      A more complex usage could be to override visiting methods for
      specific instructions, by placing them into the dispatch table.
  """

  def __init__(self, structs):
    self.structs = structs
    self._init_dispatch_table()
    self.stream = None
    self._cur_opcode = None
    self._cur_args = []

  def process_expr(self, expr: List[int]):
    """ Process (visit) a DWARF expression. expr should be a list of
        (integer) byte values.
    """
    self.save_expr = expr
    self.stream = BytesIO(bytelist2string(expr))

    while True:
      # Get the next opcode from the stream. If nothing is left in the
      # stream, we're done.
      byte = self.stream.read(1)
      if len(byte) == 0:
        break

      # Decode the opcode
      self._cur_opcode = ord(byte)

      # Will be filled in by the visitor
      self._cur_args = []

      # Dispatch to a visitor function
      visitor = self._dispatch_table.get(self._cur_opcode, self._default_visitor)
      visitor(self._cur_opcode)

      # Finally call the post-visit function
      ret = self._after_visit(self._cur_opcode, self._cur_args)
      if ret is not None and ret is False:
        break

  def _after_visit(self, opcode, args):
    pass

  def _default_visitor(self, opcode):
    pass

  def _visit_OP_with_no_args(self, opcode):
    self._cur_args = []

  def _visit_OP_addr(self, opcode):
    self._cur_args = [
        struct_parse(self.structs.Dwarf_target_addr(''), self.stream)]

  def _make_visitor_arg_struct(self, struct_arg):
    """ Create a visitor method for an opcode that that accepts a single
        argument, specified by a struct.
    """
    def visitor(opcode):
      self._cur_args = [struct_parse(struct_arg, self.stream)]
    return visitor

  def _make_visitor_arg_struct2(self, struct_arg1, struct_arg2):
    """ Create a visitor method for an opcode that that accepts two
        arguments, specified by structs.
    """
    def visitor(opcode):
      self._cur_args = [
          struct_parse(struct_arg1, self.stream),
          struct_parse(struct_arg2, self.stream)]
    return visitor

  def _make_visitor_arg_variable_len(self):
    """ Create a visitor method for an opcode that that accepts two
        arguments, specified by structs.
    """
    def visitor(opcode):
      assert(self.stream is not None)
      n = struct_parse(self.structs.Dwarf_uleb128(''), self.stream)
      self._cur_args = [self.stream.read(n)]
    return visitor

  def _init_dispatch_table(self):
    self._dispatch_table = {}

    def add(opcode_name, func):
      self._dispatch_table[DW_OP_name2opcode[opcode_name]] = func

    add('DW_OP_addr', self._visit_OP_addr)
    add('DW_OP_const1u', self._make_visitor_arg_struct(self.structs.Dwarf_uint8('')))
    add('DW_OP_const1s', self._make_visitor_arg_struct(self.structs.Dwarf_int8('')))
    add('DW_OP_const2u', self._make_visitor_arg_struct(self.structs.Dwarf_uint16('')))
    add('DW_OP_const2s', self._make_visitor_arg_struct(self.structs.Dwarf_int16('')))
    add('DW_OP_const4u', self._make_visitor_arg_struct(self.structs.Dwarf_uint32('')))
    add('DW_OP_const4s', self._make_visitor_arg_struct(self.structs.Dwarf_int32('')))
    add('DW_OP_const8u', self._make_visitor_arg_struct(self.structs.Dwarf_uint64('')))
    add('DW_OP_const8s', self._make_visitor_arg_struct(self.structs.Dwarf_int64('')))
    add('DW_OP_constu', self._make_visitor_arg_struct(self.structs.Dwarf_uleb128('')))
    add('DW_OP_consts', self._make_visitor_arg_struct(self.structs.Dwarf_sleb128('')))
    add('DW_OP_pick', self._make_visitor_arg_struct(self.structs.Dwarf_uint8('')))
    add('DW_OP_plus_uconst', self._make_visitor_arg_struct(self.structs.Dwarf_uleb128('')))
    add('DW_OP_bra', self._make_visitor_arg_struct(self.structs.Dwarf_int16('')))
    add('DW_OP_skip', self._make_visitor_arg_struct(self.structs.Dwarf_int16('')))
    add('DW_OP_fbreg', self._make_visitor_arg_struct(self.structs.Dwarf_sleb128('')))
    add('DW_OP_regx', self._make_visitor_arg_struct(self.structs.Dwarf_uleb128('')))
    add('DW_OP_bregx', self._make_visitor_arg_struct2(self.structs.Dwarf_uleb128(''), self.structs.Dwarf_sleb128('')))
    add('DW_OP_piece', self._make_visitor_arg_struct(self.structs.Dwarf_uleb128('')))
    add('DW_OP_bit_piece', self._make_visitor_arg_struct2(self.structs.Dwarf_uleb128(''), self.structs.Dwarf_uleb128('')))
    add('DW_OP_deref_size', self._make_visitor_arg_struct(self.structs.Dwarf_int8('')))
    add('DW_OP_xderef_size', self._make_visitor_arg_struct(self.structs.Dwarf_int8('')))
    add('DW_OP_call2', self._make_visitor_arg_struct(self.structs.Dwarf_uint16('')))
    add('DW_OP_call4', self._make_visitor_arg_struct(self.structs.Dwarf_uint32('')))
    add('DW_OP_call_ref', self._make_visitor_arg_struct(self.structs.Dwarf_offset('')))
    add('DW_OP_implicit_value', self._make_visitor_arg_variable_len())
    for n in range(0, 32):
      add('DW_OP_lit%s' % n, self._visit_OP_with_no_args)
      add('DW_OP_reg%s' % n, self._visit_OP_with_no_args)
      add('DW_OP_breg%s' % n, self._make_visitor_arg_struct(self.structs.Dwarf_sleb128('')))
    for opname in [
        'DW_OP_deref', 'DW_OP_dup', 'DW_OP_drop', 'DW_OP_over',
        'DW_OP_swap', 'DW_OP_swap', 'DW_OP_rot', 'DW_OP_xderef',
        'DW_OP_abs', 'DW_OP_and', 'DW_OP_div', 'DW_OP_minus',
        'DW_OP_mod', 'DW_OP_mul', 'DW_OP_neg', 'DW_OP_not',
        'DW_OP_plus', 'DW_OP_shl', 'DW_OP_shr', 'DW_OP_shra',
        'DW_OP_xor', 'DW_OP_eq', 'DW_OP_ge', 'DW_OP_gt',
        'DW_OP_le', 'DW_OP_lt', 'DW_OP_ne', 'DW_OP_nop',
        'DW_OP_push_object_address', 'DW_OP_form_tls_address',
        'DW_OP_call_frame_cfa'
    ]:
      add(opname, self._visit_OP_with_no_args)


class ExprEval(StaticExprEvaluator):
  """ A concrete visitor for DWARF expressions that dumps a textual
      representation of the complete expression.

      Usage: after creation, call process_expr, and then get_str for a
      semicolon-delimited string representation of the decoded expression.
  """

  def __init__(self, structs, arch):
    super(ExprEval, self).__init__(structs)
    self._arch = arch
    self._init_lookups()
    self._frame_base = None
    self._stack: List[Union[int, str, ExprOp]] = list()
    self._is_stack_value = False
    self._is_setting_frame_base = False

  def clear(self):
    self._stack = list()
    self._is_stack_value = False
    self._is_setting_frame_base = False

  @property
  def stack(self):
    return self._stack

  @property
  def frame_base(self):
    return self._frame_base

  @property
  def value(self):
    return self._stack[-1]

  def set_frame_base(self, expr):
    if expr is None:
      self._frame_base = None
      return
    self.clear()
    self._is_setting_frame_base = True
    self.process_expr(expr)
    self._is_setting_frame_base = False
    if self._stack == [ExprOp.CFA]:
      self._frame_base = ExprOp.CFA
    else:
      self._frame_base = None

  def _init_lookups(self):
    self._const_ops = set([
        DW_OP_addr,
        DW_OP_const1u, DW_OP_const1s, DW_OP_const2u, DW_OP_const2s,
        DW_OP_const4u, DW_OP_const4s, DW_OP_constu, DW_OP_consts,
        DW_OP_const8u, DW_OP_const8s
    ])
    self._ops_with_decimal_arg = set([
        'DW_OP_const1u', 'DW_OP_const1s', 'DW_OP_const2u', 'DW_OP_const2s',
        'DW_OP_const4u', 'DW_OP_const4s', 'DW_OP_constu', 'DW_OP_consts',
        'DW_OP_pick', 'DW_OP_plus_uconst', 'DW_OP_bra', 'DW_OP_skip',
        'DW_OP_fbreg', 'DW_OP_piece', 'DW_OP__size',
        'DW_OP_xderef_size', 'DW_OP_regx', 'DW_OP_const8u', 'DW_OP_const8s'])

    for n in range(0, 32):
      self._ops_with_decimal_arg.add('DW_OP_breg%s' % n)

    self._ops_with_two_decimal_args = set([
        'DW_OP_bregx', 'DW_OP_bit_piece'])

    self._ops_with_hex_arg = set(
        ['DW_OP_addr', 'DW_OP_call2', 'DW_OP_call4', 'DW_OP_call_ref'])

    self._dynamic_ops = set([
        DW_OP_shl,
        DW_OP_deref,
        DW_OP_deref_size,
        DW_OP_pick,
        DW_OP_abs
    ])
    self._unsupported_ops = set([
        DW_OP_piece,
        DW_OP_dup,
        DW_OP_bra
    ])

  def _after_visit(self, opcode, args) -> Optional[bool]:
    if opcode == DW_OP_stack_value:
      # The value on the stack is the actual value, not the location.
      self._is_stack_value = True
      return False
    elif opcode in self._const_ops:
      self._stack.append(args[0])
    elif DW_OP_lit0 <= opcode and opcode <= DW_OP_lit31:
      self._stack.append(opcode - DW_OP_lit0)
    elif DW_OP_reg0 <= opcode and opcode <= DW_OP_reg31:
      regnum = opcode - DW_OP_reg0
      self._stack.append(describe_reg_name(regnum, self._arch))
    elif DW_OP_breg0 <= opcode and opcode <= DW_OP_breg31:
      regnum = opcode - DW_OP_breg0
      regname = describe_reg_name(regnum, self._arch)
      self._stack.extend([regname, args[0], ExprOp.ADD])
    elif opcode == DW_OP_fbreg and isinstance(self._frame_base, ExprOp):
      self._stack.extend([self._frame_base, args[0], ExprOp.ADD])
    elif opcode == DW_OP_fbreg and self._frame_base is None:
      self._stack.extend([ExprOp.CFA, args[0], ExprOp.ADD])
    elif opcode == DW_OP_regx:
      regnum = args[0]
      regname = describe_reg_name(regnum, self._arch)
      self._stack.append(regname)
    elif opcode == DW_OP_bregx:
      regnum = args[0]
      regname = describe_reg_name(regnum, self._arch)
      self._stack.extend([regname, args[1], ExprOp.ADD])
    elif opcode == DW_OP_piece and len(self._stack) == 0:
      # if you run into a DW_OP_piece and the expression stack is
      # empty, then the bytes for the piece are optimized out.
      pass
    elif opcode == DW_OP_piece and len(self._stack) > 0 and isinstance(self.stack[-1], str):
      # if you run into a DW_OP_piece and it refers to a register
      # then select the subrange.
      self._stack.extend([args[0], ExprOp.VAR_FIELD])
    elif opcode == DW_OP_bit_piece and len(self._stack) == 0:
      # if you run into a DW_OP_bit_piece and the expression stack is
      # empty, then the bits for the piece are optimized out.
      pass
    elif opcode == DW_OP_bit_piece and len(self._stack) > 0 and isinstance(self.stack[-1], str) and args[1] == 0:
      # the location is only the lower `args[0]` bits of the register.
      pass
    elif opcode == DW_OP_call_frame_cfa:
      # assert(self._is_setting_frame_base)
      self._stack.append(ExprOp.CFA)
    elif opcode in self._dynamic_ops:
      self._stack.append(ExprOp.DYNAMIC)
      return False
    elif opcode == DW_OP_plus:
      self._stack.append(ExprOp.ADD)
    elif opcode == DW_OP_not:
      self._stack.append(ExprOp.NOT)
    elif opcode == DW_OP_neg:
      self._stack.append(ExprOp.NEG)
    elif opcode == DW_OP_or:
      self._stack.append(ExprOp.OR)
    elif opcode == DW_OP_ne:
      self._stack.append(ExprOp.NE)
    elif opcode == DW_OP_eq:
      self._stack.append(ExprOp.EQ)
    elif opcode == DW_OP_le:
      self._stack.append(ExprOp.LE)
    elif opcode == DW_OP_ge:
      self._stack.append(ExprOp.GE)
    elif opcode == DW_OP_gt:
      self._stack.append(ExprOp.GT)
    elif opcode == DW_OP_lt:
      self._stack.append(ExprOp.LT)
    elif opcode == DW_OP_and:
      self._stack.append(ExprOp.AND)
    elif opcode == DW_OP_minus:
      self._stack.append(ExprOp.MINUS)
    elif opcode == DW_OP_shra:
      self._stack.append(ExprOp.ASHR)
    elif opcode == DW_OP_xor:
      self._stack.append(ExprOp.XOR)
    elif opcode == DW_OP_mul:
      self._stack.append(ExprOp.MUL)
    elif opcode == DW_OP_mod:
      self._stack.append(ExprOp.MOD)
    elif opcode == DW_OP_div:
      self._stack.append(ExprOp.DIV)
    elif opcode == DW_OP_shr:
      self._stack.append(ExprOp.SHR)
    elif opcode == DW_OP_plus_uconst:
      self._stack.append(ExprOp.PLUS_IMM)
      self._stack.append(args[0])
    elif opcode == DW_OP_over:
      self._stack.append(ExprOp.OVER)
    elif opcode == DW_OP_implicit_value:
      v = int.from_bytes(args[0], 'little')
      self._stack.append(v)
      self._is_stack_value = True

      # print('Expr:',[hex(x) for x in self.save_expr])
      # print('Args:', args)
      # print('Stack:',self._stack)
      # print('Frame:',self._frame_base)
      # raise Exception(f'unimplemented opcode: {hex(opcode)} {DW_OP_opcode2name.get(opcode,"UNK")}')

    elif DW_OP_lo_user <= opcode and opcode <= DW_OP_hi_user:
      self._stack.append(ExprOp.UNSUPPORTED)
      return False
    elif opcode in self._unsupported_ops:
      self._stack.append(ExprOp.UNSUPPORTED)
      return False
    else:
      if not self._is_setting_frame_base:
        print('Expr:', [hex(x) for x in self.save_expr])
        print('Args:', args)
        print('Stack:', self._stack)
        print('Frame:', self._frame_base)
        raise Exception(
            f'unimplemented opcode: '
            f'{hex(opcode)} {DW_OP_opcode2name.get(opcode,"UNK")}\nFrame: {self._frame_base}')


"""
DW_OP_entry_value

The DW_OP_entry_value operation pushes a value that had a known location
upon entering the current subprogram.  It uses two operands: an unsigned
LEB128 length, followed by a block containing a DWARF expression or
a simple register location description.  The length gives the length
in bytes of the block.  If the block contains a register location
description, DW_OP_entry_value pushes the value that register had upon
entering the current subprogram.  If the block contains a DWARF expression,
the DWARF expression is evaluated as if it has been evaluated upon entering
the current subprogram.  The DWARF expression should not assume any values
being present on the DWARF stack initially and should result in exactly one
value being added to the DWARF stack in the end.  That value is then the value
being pushed by the DW_OP_entry_value operation.  DW_OP_push_object_address
is not meaningful inside of this DWARF expression.
"""


class LocExprParser(StaticExprEvaluator):
  """ A concrete visitor for DWARF expressions that dumps a textual
      representation of the complete expression.

      Usage: after creation, call process_expr, and then get_str for a
      semicolon-delimited string representation of the decoded expression.
  """

  def __init__(self, structs, arch):
    super(LocExprParser, self).__init__(structs)
    self._arch = arch
    self._init_lookups()
    self._frame_base = None
    self._stack: List[Union[int, str, ExprOp]] = list()
    self._is_stack_value = False
    self._is_setting_frame_base = False

  def clear(self):
    self._stack = list()
    self._is_stack_value = False
    self._is_setting_frame_base = False
    self._loc_type = None

  def reset(self):
    self._stack = list()
    self._is_stack_value = False
    self._is_setting_frame_base = False
    self._loc_type = None

  def parse(self, loc_expr):
    self.clear()
    self.process_expr(loc_expr)
    if len(self._stack) == 0:
      self._loc_type = None
    elif self._stack[-1] == ExprOp.DYNAMIC:
      self._loc_type = LocationType.DYNAMIC
    elif self._stack[-1] == ExprOp.UNSUPPORTED:
      self._loc_type = LocationType.UNSUPPORTED
    else:
      if len(self._stack) == 1 and isinstance(self._stack[-1], int):
        if self._is_stack_value:
          self._loc_type = None
        else:
          self._loc_type = LocationType.STATIC_GLOBAL
      else:
        self._loc_type = LocationType.STATIC_LOCAL

  @property
  def location_type(self):
    return self._loc_type

  @property
  def stack(self):
    return self._stack

  @property
  def frame_base(self):
    return self._frame_base

  @property
  def value(self):
    return self._stack[-1]

  def set_frame_base(self, expr):
    if expr is None:
      self._frame_base = None
      return
    self.clear()
    self._is_setting_frame_base = True
    self.process_expr(expr)
    self._is_setting_frame_base = False
    if self._stack == [ExprOp.CFA]:
      self._frame_base = ExprOp.CFA
    else:
      self._frame_base = None

  def _init_lookups(self):
    self._const_ops = set([
        DW_OP_addr,
        DW_OP_const1u, DW_OP_const1s, DW_OP_const2u, DW_OP_const2s,
        DW_OP_const4u, DW_OP_const4s, DW_OP_constu, DW_OP_consts,
        DW_OP_const8u, DW_OP_const8s
    ])
    self._ops_with_decimal_arg = set([
        'DW_OP_const1u', 'DW_OP_const1s', 'DW_OP_const2u', 'DW_OP_const2s',
        'DW_OP_const4u', 'DW_OP_const4s', 'DW_OP_constu', 'DW_OP_consts',
        'DW_OP_pick', 'DW_OP_plus_uconst', 'DW_OP_bra', 'DW_OP_skip',
        'DW_OP_fbreg', 'DW_OP_piece', 'DW_OP__size',
        'DW_OP_xderef_size', 'DW_OP_regx', 'DW_OP_const8u', 'DW_OP_const8s'])

    for n in range(0, 32):
      self._ops_with_decimal_arg.add('DW_OP_breg%s' % n)

    self._ops_with_two_decimal_args = set([
        'DW_OP_bregx', 'DW_OP_bit_piece'])

    self._ops_with_hex_arg = set(
        ['DW_OP_addr', 'DW_OP_call2', 'DW_OP_call4', 'DW_OP_call_ref'])

    self._dynamic_ops = set([
        DW_OP_shl,
        DW_OP_deref,
        DW_OP_deref_size,
        DW_OP_pick,
        DW_OP_abs
    ])
    self._unsupported_ops = set([
        DW_OP_piece,
        DW_OP_bit_piece,
        DW_OP_dup,
        DW_OP_bra,
        0x2,
        0x0
    ])

  def _reg_list(self):
    if self._arch == "AArch64":
      return _REG_NAMES_AArch64
    if self._arch == "x86":
      return _REG_NAMES_x86
    if self._arch == "x64":
      return _REG_NAMES_x64
    if self._arch == 'ARM':
      return _REG_NAMES_ARM
    if self._arch == 'MIPS':
      return _REG_NAMES_MIPS
    if self._arch == 'PowerPC':
      return _REG_NAMES_POWERPC
    assert False, 'unrecognized arch: %s' % self._arch

  def _after_visit(self, opcode, args) -> Optional[bool]:
    if opcode == DW_OP_stack_value:
      # The value on the stack is the actual value, not the location.
      self._is_stack_value = True
      return False
    elif opcode in self._const_ops:
      self._stack.append(args[0])
    elif DW_OP_lit0 <= opcode and opcode <= DW_OP_lit31:
      self._stack.append(opcode - DW_OP_lit0)
    elif DW_OP_reg0 <= opcode and opcode <= DW_OP_reg31:
      regnum = opcode - DW_OP_reg0
      self._stack.append(describe_reg_name(regnum, self._arch))
    elif DW_OP_breg0 <= opcode and opcode <= DW_OP_breg31:
      regnum = opcode - DW_OP_breg0
      regname = describe_reg_name(regnum, self._arch)
      self._stack.extend([regname, args[0], ExprOp.ADD])
      self._stack.append(ExprOp.DYNAMIC)
      return False
    elif opcode == DW_OP_fbreg and isinstance(self._frame_base, ExprOp):
      self._stack.extend([self._frame_base, args[0], ExprOp.ADD])
    elif opcode == DW_OP_fbreg and self._frame_base is None:
      self._stack.extend([ExprOp.CFA, args[0], ExprOp.ADD])
    elif opcode == DW_OP_regx:
      regnum = args[0]
      if regnum < len(self._reg_list()):
        regname = describe_reg_name(regnum, self._arch)
        self._stack.append(regname)
      else:
        print('Unsupported reg num:', regnum)
    elif opcode == DW_OP_bregx:
      regnum = args[0]
      if regnum < len(self._reg_list()):
        regname = describe_reg_name(regnum, self._arch)
        self._stack.extend([regname, args[1], ExprOp.ADD])
      else:
        print('Unsupported reg num:', regnum)
    elif opcode == DW_OP_piece and len(self._stack) == 0:
      # if you run into a DW_OP_piece and the expression stack is
      # empty, then the bytes for the piece are optimized out.
      pass
    elif opcode == DW_OP_piece and len(self._stack) > 0 and isinstance(self.stack[-1], str):
      # if you run into a DW_OP_piece and it refers to a register
      # then select the subrange.
      self._stack.extend([args[0], ExprOp.VAR_FIELD])
    elif opcode == DW_OP_bit_piece and len(self._stack) == 0:
      # if you run into a DW_OP_bit_piece and the expression stack is
      # empty, then the bits for the piece are optimized out.
      pass
    elif opcode == DW_OP_bit_piece and len(self._stack) > 0 and isinstance(self.stack[-1], str) and args[1] == 0:
      # the location is only the lower `args[0]` bits of the register.
      pass
    elif opcode == DW_OP_call_frame_cfa:
      # assert(self._is_setting_frame_base)
      self._stack.append(ExprOp.CFA)
    elif opcode in self._dynamic_ops:
      self._stack.append(ExprOp.DYNAMIC)
      return False
    elif opcode == DW_OP_plus:
      self._stack.append(ExprOp.ADD)
    elif opcode == DW_OP_not:
      self._stack.append(ExprOp.NOT)
    elif opcode == DW_OP_neg:
      self._stack.append(ExprOp.NEG)
    elif opcode == DW_OP_or:
      self._stack.append(ExprOp.OR)
    elif opcode == DW_OP_ne:
      self._stack.append(ExprOp.NE)
    elif opcode == DW_OP_eq:
      self._stack.append(ExprOp.EQ)
    elif opcode == DW_OP_le:
      self._stack.append(ExprOp.LE)
    elif opcode == DW_OP_ge:
      self._stack.append(ExprOp.GE)
    elif opcode == DW_OP_gt:
      self._stack.append(ExprOp.GT)
    elif opcode == DW_OP_lt:
      self._stack.append(ExprOp.LT)
    elif opcode == DW_OP_and:
      self._stack.append(ExprOp.AND)
    elif opcode == DW_OP_minus:
      self._stack.append(ExprOp.MINUS)
    elif opcode == DW_OP_shra:
      self._stack.append(ExprOp.ASHR)
    elif opcode == DW_OP_xor:
      self._stack.append(ExprOp.XOR)
    elif opcode == DW_OP_mul:
      self._stack.append(ExprOp.MUL)
    elif opcode == DW_OP_mod:
      self._stack.append(ExprOp.MOD)
    elif opcode == DW_OP_div:
      self._stack.append(ExprOp.DIV)
    elif opcode == DW_OP_shr:
      self._stack.append(ExprOp.SHR)
    elif opcode == DW_OP_plus_uconst:
      self._stack.append(ExprOp.PLUS_IMM)
      self._stack.append(args[0])
    elif opcode == DW_OP_over:
      self._stack.append(ExprOp.OVER)
    elif opcode == DW_OP_implicit_value:
      v = int.from_bytes(args[0], 'little')
      self._stack.append(v)
      self._is_stack_value = True

      # print('Expr:',[hex(x) for x in self.save_expr])
      # print('Args:', args)
      # print('Stack:',self._stack)
      # print('Frame:',self._frame_base)
      # raise Exception(f'unimplemented opcode: {hex(opcode)} {DW_OP_opcode2name.get(opcode,"UNK")}')

    elif DW_OP_lo_user <= opcode and opcode <= DW_OP_hi_user:
      self._stack.append(ExprOp.UNSUPPORTED)
      return False
    elif opcode in self._unsupported_ops:
      self._stack.append(ExprOp.UNSUPPORTED)
      return False
    else:
      if not self._is_setting_frame_base:
        print('Expr:', [hex(x) for x in self.save_expr])
        print('Args:', args)
        print('Stack:', self._stack)
        print('Frame:', self._frame_base)
        raise Exception(
            f'unimplemented opcode: '
            f'{hex(opcode)} {DW_OP_opcode2name.get(opcode,"UNK")}\nFrame: {self._frame_base}')

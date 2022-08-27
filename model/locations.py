# Copyright(c) 2021-2022 Vector 35 Inc
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

from enum import Enum
from dataclasses import dataclass
from typing import Union, Tuple


class ExprOp(Enum):
  CFA = 0  # Canonical frame address
  ADD = 1
  VAR_FIELD = 2
  NE = 3
  GE = 4
  GT = 5
  LE = 6
  LT = 7
  EQ = 8
  AND = 9
  OR = 10
  MINUS = 11
  ASHR = 12
  MUL = 13
  MOD = 14
  SHR = 15
  PLUS_IMM = 16
  OVER = 17
  DIV = 18
  NOT = 19
  NEG = 20
  XOR = 21
  DYNAMIC = 0xfffe
  UNSUPPORTED = 0xffff


class LocationType(Enum):
  STATIC_GLOBAL = 0
  STATIC_LOCAL = 1
  DYNAMIC = 2
  UNSUPPORTED = 3


LocationExpression = Tuple[Union[int, str, ExprOp], ...]


@dataclass(eq=True, frozen=True)
class Location:
  begin: int
  end: int
  type: LocationType
  expr: LocationExpression

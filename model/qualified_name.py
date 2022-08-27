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


from typing import Union


class QualifiedName(tuple):
  def __new__(cls, *args):
    if len(args) == 1:
      if isinstance(args[0], str):
        return tuple.__new__(QualifiedName, args[0:1])
      else:
        return tuple.__new__(QualifiedName, args[0])
    else:
      return tuple.__new__(QualifiedName, args)

  def __bool__(self) -> bool:
    return len(self) > 0

  def __repr__(self) -> str:
    return str(self)

  def __str__(self) -> str:
    return '::'.join(self)

  def concat(self, rhs: Union[str, "QualifiedName"]) -> "QualifiedName":
    if isinstance(rhs, str):
      return QualifiedName(*self, rhs)
    else:
      return QualifiedName(*self, *rhs)

  @property
  def is_anonymous(self) -> bool:
    return len(self) == 0 or self[-1] == ''

  @property
  def is_empty(self) -> bool:
    return len(self) == 0

  @property
  def parent(self) -> "QualifiedName":
    if len(self) > 1:
      return QualifiedName(*self[:-1])
    else:
      return QualifiedName()

  @property
  def local_name(self) -> str:
    if len(self) > 0:
      return self[-1]
    else:
      return ''

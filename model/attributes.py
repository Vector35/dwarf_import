# Copyright(c) 2021-2023 Vector 35 Inc
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

from typing import Any, Optional, Union
from dataclasses import dataclass


@dataclass
class Attribute:
  name: str
  type: Any

  def __hash__(self):
    return self.name.__hash__()

  def __eq__(self, other):
    if isinstance(other, Attribute):
      return self.name == other.name and self.type == other.type
    elif isinstance(other, str):
      return self.name == other
    return NotImplemented


class AttributeSet(dict):
  def __getitem__(self, key: Union[str, Attribute]) -> Optional[Any]:
    if isinstance(key, Attribute):
      key = key.name
    if super().__contains__(key):
      return super().__getitem__(key)
    else:
      return None

  def __setitem__(self, key: Union[str, Attribute], value: Any) -> None:
    if isinstance(key, Attribute):
      key = key.name
    return super().__setitem__(key, value)

  def __contains__(self, key: Union[str, Attribute]) -> bool:
    if isinstance(key, Attribute):
      key = key.name
    return super().__contains__(key)

  def append(self, key: Union[str, Attribute], value) -> None:
    v = self[key]
    if isinstance(v, list):
      if value not in v:
        v.append(value)
    elif v is None:
      self[key] = [value]

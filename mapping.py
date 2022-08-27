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

from uuid import UUID
from typing import MutableMapping, Optional
from .model.concrete_elements import Element


class BinjaMap(object):
  def __init__(self, binary_view):
    self._binary_view = binary_view
    self._version_table: MutableMapping[UUID, int] = dict()

  def is_newer(self, element: Element):
    if element.uuid not in self._version_table:
      return True
    return element.version > self._version_table[element.uuid]

  def commit(self, element: Element) -> Optional[Element]:
    if element.uuid in self._version_table:
      if element.version <= self._version_table[element.uuid]:
        return None
    self._version_table[element.uuid] = element.version
    return element

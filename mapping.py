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

from uuid import UUID
from typing import BinaryIO, Mapping, Union, Iterable, Any, Optional
from .model import Module
from .model.elements import Function, Element, Component
from binaryninja.binaryview import BinaryView, BinaryViewType
import binaryninja as bn
from io import BytesIO
import os


class MappedModel:
  def __init__(self, filename: str = None, debug_root: str = None, debug_file: str = None, binary_view = None):
    if filename is None and binary_view is None:
      raise Exception('Must specify either a filename or binary view.')
    if binary_view is None:
      self.binary_view = BinaryViewType.get_view_of_file(filename, update_analysis=False)
    else:
      self.binary_view = binary_view
    assert(self.binary_view is not None)
    self.module = Module()
    self.mapping = BinjaMap(self.binary_view)
    self.debug_root = debug_root
    self.debug_file = debug_file

  def __del__(self):
    if self.binary_view is not None:
      self.binary_view.abort_analysis()
      self.binary_view.file.close()

  def has_debug_info(self) -> bool:
    if self.binary_view.view_type != 'ELF':
      return False
    if self.debug_file != None and os.path.isfile(self.debug_file):
      return True
    from elftools.elf.elffile import ELFFile
    raw_view = self.binary_view.file.raw
    elf_file = ELFFile(BytesIO(raw_view.read(raw_view.start, len(raw_view))))
    return ELF_has_debug_info(elf_file)

  def get_debug_info(self) -> Optional[Any]:
    return self._get_DWARF_debug_info()

  def _get_DWARF_debug_info(self) -> Optional[Any]:
    if self.binary_view.view_type != 'ELF':
      return None

    from elftools.elf.elffile import ELFFile

    if self.debug_file != None:
      import os
      if os.path.isfile(self.debug_file):
        elf_file = ELFFile(open(self.debug_file, 'rb'))
        if ELF_has_debug_info(elf_file):
          return elf_file

    if self.binary_view.view_type == 'ELF':
      raw_view = self.binary_view.file.raw
      elf_file = ELFFile(BytesIO(raw_view.read(raw_view.start, len(raw_view))))
      if ELF_has_debug_info(elf_file):
        return elf_file

    return None

  def print_outline(self, element = None, indent=0):
    if element is None:
      self.print_outline(self.module)
      return
    print('  '*indent, end='')
    print(element.name)
    if isinstance(element, Module):
      for m in element.submodules:
        self.print_outline(m, indent+1)
      for c in element.components:
        self.print_outline(c, indent+1)
    elif isinstance(element, Component):
      for f in element.functions:
        print('  '*(indent+1), end='')
        print(f.name)


def ELF_has_debug_info(elf_file) -> bool:
  if elf_file.get_section_by_name('.debug_info') or elf_file.get_section_by_name('.zdebug_info'):
    return True
  else:
    return False


BinaryModel = MappedModel


class BinjaMap(object):
  def __init__(self, binary_view):
    self._binary_view = binary_view
    self._version_table: Mapping[UUID, int] = dict()

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

  def to_binja(self, items: Union[Iterable[Any], Any]):
    element = self.map_element_to_binja(items)
    if element is not None:
      yield element
    try:
      iterator = iter(items)
    except TypeError:
      pass  # not iterable
    else:
      for item in iterator:
        yield self.map_element_to_binja(item)

  def map_element_to_binja(self, item):
    if isinstance(item, Function):
      return self._binary_view.get_function_at(item.start)
    return None

  def from_binja(self, items: Union[Iterable[Any], Any]):
    element = self.map_element_from_binja(items)
    if element is not None:
      yield element
    try:
      iterator = iter(items)
    except TypeError:
      pass  # not iterable
    else:
      for item in iterator:
        yield self.map_element_from_binja(item)

  def map_element_from_binja(self, item: Any):
    if isinstance(item, bn.Function):
      binja_function: bn.Function = item
      function = Function(name=binja_function.name, start=binja_function.start)
      function.no_return = not binja_function.can_return
      self._version_table[function.uuid] = function.version

      function.set_attribute('function_type', binja_function.function_type)
      return function
    else:
      return None

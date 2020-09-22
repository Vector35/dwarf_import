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

from .observer import Observable
from .elements import Component, Function
from .touch_flags import TouchFlags
from uuid import uuid4
from itertools import chain
from typing import Generator, Optional


class Module(Observable):
  def __init__(self, parent=None, name: Optional[str] = None):
    super().__init__(parent)
    self._supermodule = parent
    self._binary_view = None
    self._uuid = uuid4()
    self._name = name
    self._submodules = list()
    self._components = list()
    self._constraints = dict()

  def __repr__(self):
    n = '<unnamed module>, ' if self.name is None else f'{self.name}, '
    return f'<Module: {n}{len(self._components)} components, {len(self._submodules)} submodules>'

  def __len__(self):
    return len(self._submodules) + len(self._components)

  @property
  def supermodule(self):
    return self._supermodule

  @property
  def binary_view(self):
    return self._binary_view

  @property
  def uuid(self):
    return self._uuid

  @property
  def name(self):
    return self._name

  @name.setter
  def name(self, value):
    if value != self._name:
      old_name = self._name
      self._name = value
      self.notify('submodule_renamed', TouchFlags.TOUCHED_NAMES, **{'submodule': self, 'old_name': old_name})

  @property
  def submodules(self):
    return self._submodules

  @property
  def components(self):
    return self._components

  @property
  def start(self):
    if self._name == '<unreferenced components>':
      return 0xffffffff
    # TODO: Weighted-average?
    if len(self) > 0:
      addrs = list(map(lambda e: e.start, self.children()))
      if not any(map(lambda s: s is None, addrs)):
        return sum(addrs) / len(self)
    return None

  def children(self):
    return chain(self._submodules, self._components)

  def is_referenced(self):
    if len(self) > 0:
      return any(map(lambda e: e.is_referenced(), self.children()))
    else:
      return False

  def add_submodule(self, submodule):
    submodule._supermodule = self
    submodule._observable_parent = self
    self._submodules.append(submodule)
    self.notify('submodules_added', TouchFlags.TOUCHED_FUNCTION_SET, **{'submodules': [submodule]})
    return submodule

  def get_submodule(self, name):
    for m in self._submodules:
      if m.name == name:
        return m
    return None

  def add_component(self, c):
    c._module = self
    self._components.append(c)
    self.notify('components_added', TouchFlags.TOUCHED_FUNCTION_SET, **{'components': [c]})
    return c

  def remove_component(self, c: Component):
    self._components.remove(c)
    self.notify('components_removed', TouchFlags.TOUCHED_FUNCTION_SET, **{'components': [c]})

  def add_constraint(self, cons_id, cons):
    self._constraints[cons_id] = cons

  def traverse_modules(self) -> Generator["Module", None, None]:
    yield self
    for submodule in self._submodules:
      for m in submodule.traverse_modules():
        yield m

  def traverse_components(self) -> Generator[Component, None, None]:
    for component in self._components:
      yield component
    for submodule in self._submodules:
      for component in submodule.traverse_components():
        yield component

  def get_function_at(self, start: int) -> Optional[Function]:
    for c in self.traverse_components():
      for f in c.functions:
        if f.start == start:
          return f
    return None

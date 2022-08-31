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

import sys
from dataclasses import dataclass, field
from typing import Optional, List, Union, Iterable, Generator
from uuid import UUID, uuid4
from enum import Enum
from .observer import Observable
from .concrete_elements import Element, Function, Type, Variable
from .attributes import AttributeSet


class AnalysisRealm(Enum):
  INTERNAL = 0
  EXTERNAL = 1
  RUNTIME = 2


class Visibility(Enum):
  PUBLIC = 0
  PRIVATE = 1


class Selector(Enum):
  ELEMENT_SET = 0
  UNION = 1
  INTERSECTION = 2
  SYMMETRIC_DIFFERENCE = 3


@dataclass
class ComponentMember:
  element: Element
  visibility: Visibility = Visibility.PRIVATE


ComponentOperand = Union[ComponentMember, "Component"]


@dataclass
class Component:
  model: Optional[Observable]
  name: str
  uuid: UUID = field(init=False, default_factory=uuid4)
  parent: Optional["Component"] = None
  realm: AnalysisRealm = AnalysisRealm.INTERNAL
  selector: Selector = Selector.ELEMENT_SET
  operands: List[ComponentOperand] = field(default_factory=list)
  attributes: AttributeSet = field(default_factory=AttributeSet)

  def __hash__(self):
    return hash(self.uuid)

  def __len__(self):
    c = 0
    for opnd in self.operands:
      if isinstance(opnd, Component):
        c += len(opnd)
      else:
        c += 1
    return c

  def __contains__(self, el: Element):
    assert(el is not None)
    if self.is_leaf():
      for opnd in self.operands:
        assert(isinstance(opnd, ComponentMember))
        if el == opnd.element:
          return True
    return False

  def __repr__(self):
    return f'<Component: {self.name}, {self.uuid=}>'

  @property
  def pathname(self) -> str:
    tmp = []
    p = self
    while p is not None and p.parent is not None:
      tmp.insert(0, p.name)
      p = p.parent
    return '/'.join(tmp)

  def rename(self, value: str):
    if value == self.name:
      return
    old_name = self.name
    self.name = value
    if self.model is not None:
      self.model.notify('component_renamed', **{'component': self, 'old_name': old_name})

  def set_model(self, m):
    self.model = m
    if self.selector != Selector.ELEMENT_SET:
      for opnd in self.operands:
        if isinstance(opnd, Component):
          opnd.set_model(m)

  @property
  def component_count(self) -> int:
    if self.is_leaf():
      return 0
    else:
      return len(self.operands)

  @property
  def lowerbound(self) -> int:
    low = sys.maxsize
    for opnd in self.operands:
      if isinstance(opnd, Component):
        low = min(opnd.lowerbound, low)
      elif isinstance(opnd, ComponentMember):
        el = opnd.element
        if isinstance(el, Function):
          low = min(el.lowerbound, low)
      else:
        assert False, f'{type(opnd)} is an invalid component operand'
    return low

  @property
  def upperbound(self) -> int:
    high = 0
    for opnd in self.operands:
      if isinstance(opnd, Component):
        high = max(opnd.lowerbound, high)
      elif isinstance(opnd, ComponentMember):
        el = opnd.element
        if isinstance(el, Function):
          high = max(el.upperbound, high)
    return high

  def is_internal(self) -> bool:
    return self.realm == AnalysisRealm.INTERNAL

  def is_leaf(self) -> bool:
    return self.selector == Selector.ELEMENT_SET

  def elements(self) -> Generator[Element, None, None]:
    for opnd in self.operands:
      if isinstance(opnd, Component):
        for x in opnd.elements():
          yield x
      else:
        assert(isinstance(opnd, ComponentMember))
        yield opnd.element

  def functions(self) -> Generator[Function, None, None]:
    for opnd in self.operands:
      if isinstance(opnd, Component):
        for x in opnd.functions():
          yield x
      else:
        assert(isinstance(opnd, ComponentMember))
        if isinstance(opnd.element, Function):
          yield opnd.element

  def variables(self) -> Generator[Variable, None, None]:
    for opnd in self.operands:
      if isinstance(opnd, Component):
        for x in opnd.variables():
          yield x
      else:
        assert(isinstance(opnd, ComponentMember))
        if isinstance(opnd.element, Variable):
          yield opnd.element

  def types(self) -> Generator[Type, None, None]:
    for opnd in self.operands:
      if isinstance(opnd, Component):
        for x in opnd.types():
          yield x
      else:
        assert(isinstance(opnd, ComponentMember))
        if isinstance(opnd.element, Type):
          yield opnd.element

  def components(self) -> Generator["Component", None, None]:
    if self.selector != Selector.ELEMENT_SET:
      for opnd in self.operands:
        if isinstance(opnd, Component):
          yield opnd
          for x in opnd.components():
            yield x

  def add_components(self, components: Union["Component", Iterable["Component"]]):
    if self.selector != Selector.ELEMENT_SET:
      if isinstance(components, Component):
        components = [components]
      pos = len(self.operands)
      for c in components:
        assert(c.uuid != self.uuid)
        c.parent = self
        c.set_model(self.model)
        self.operands.append(c)
      if self.model and pos < len(self.operands):
        self.model.notify('component_operands_added', **{'component': self, 'operands': list(self.operands[pos:])})
    else:
      raise Exception('Cannot add components to ELEMENT_SET')

  def add_elements(self, elements: Union[Element, Iterable[Element]]):
    if self.is_leaf():
      if isinstance(elements, Element):
        elements = [elements]
      pos = len(self.operands)
      self.operands.extend(map(lambda el: ComponentMember(el), elements))
      if self.model and pos < len(self.operands):
        self.model.notify('component_operands_added', **{'component': self, 'operands': list(self.operands[pos:])})

  def get_visibility(self, el: Element) -> Optional[Visibility]:
    if self.is_leaf():
      for opnd in self.operands:
        assert(isinstance(opnd, ComponentMember))
        if el == opnd.element:
          return opnd.visibility
    return None

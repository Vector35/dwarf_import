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

from typing import Iterable, MutableMapping, Optional, Union, Generator, Tuple, Any
from uuid import UUID
from itertools import chain

from .qualified_name import QualifiedName
from .abstract_elements import AbstractObject, AbstractFlow
from .concrete_elements import Element, Type, Variable, Constant, Function
from .component import Component, Selector
from .attributes import AttributeSet, Attribute
from .observer import Observable


class AnalysisModel(Observable):
  VERSION = 1

  def __init__(self, name: str) -> None:
    super().__init__(None)
    self.name = name
    self._elements: MutableMapping[UUID, Element] = dict()
    self._types: MutableMapping[QualifiedName, Type] = dict()
    self._constants: MutableMapping[QualifiedName, Constant] = dict()
    self._variables: MutableMapping[QualifiedName, Variable] = dict()
    self._functions: MutableMapping[int, Function] = dict()
    self._component = Component(self, 'Components', selector=Selector.UNION)
    self._abstract_objects: List[AbstractObject] = list()
    self._abstract_flows: MutableMapping[QualifiedName, AbstractFlow] = dict()
    self._metadata = AttributeSet()

  @property
  def is_empty(self) -> bool:
    if (
      len(self._types) > 0
      or len(self._constants) > 0
      or len(self._variables) > 0
      or len(self._functions) > 0
      or self._component.component_count > 0
    ):
      return False
    else:
      return True

  @property
  def metadata(self):
    return self._metadata

  def elements(self) -> Iterable[Union[Type, Constant, Variable, Function]]:
    return chain(
      self._types.values(),
      self._constants.values(),
      self._variables.values(),
      self._functions.values())

  @property
  def element_count(self) -> int:
    return len(self._types) + len(self._constants) + len(self._variables) + len(self._functions)

  def abstract_elements(self) -> Iterable[Union[AbstractObject, AbstractFlow]]:
    return chain(
      self._abstract_objects,
      self._abstract_flows.values()
    )

  @property
  def types(self) -> Iterable[Type]:
    return self._types.values()

  @property
  def constants(self) -> Iterable[Constant]:
    return self._constants.values()

  @property
  def variables(self) -> Iterable[Variable]:
    return self._variables.values()

  @property
  def functions(self) -> Iterable[Function]:
    return self._functions.values()

  @property
  def root_component(self) -> Component:
    return self._component

  def iter_components(self) -> Generator[Component, None, None]:
    def get_components(c: Component):
      for opnd in c.operands:
        if isinstance(opnd, Component):
          yield opnd
          for x in get_components(opnd):
            yield x

    for c in get_components(self._component):
      yield c

  def iter_leaf_components(self) -> Generator[Component, None, None]:
    def get_leaf_components(c: Component):
      if c.selector == Selector.ELEMENT_SET:
        yield c
      else:
        for opnd in c.operands:
          assert(isinstance(opnd, Component))
          for x in get_leaf_components(opnd):
            yield x

    for leaf in get_leaf_components(self._component):
      yield leaf

  def attributes(self) -> Generator[Tuple[Any, Attribute], None, None]:
    for e in chain(self.elements(), self.abstract_elements()):
      if e.attributes is not None:
        for attr in e.attributes:
          yield (e, attr)

  def get_element_by_name(self, qname: QualifiedName) -> Optional[Element]:
    raise NotImplementedError('get_element_by_name')

  def get_element_by_uuid(self, uuid: UUID) -> Optional[Element]:
    return self._elements.get(uuid, None)

  def get_component_by_uuid(self, uuid: UUID) -> Optional[Component]:
    for c in self.iter_components():
      if c.uuid == uuid:
        return c
    return None

  def get_function_at(self, addr: int):
    return self._functions.get(addr, None)

  def get_function_by_name(self, name: Union[QualifiedName, str]):
    if isinstance(name, str):
      name = QualifiedName(name)
    for fn in self._functions.values():
      if fn.name == name:
        return fn
    return None

  def get_type_with_name(self, typename: QualifiedName):
    return self._types.get(typename, None)

  def add_variable(self, v: Variable):
    v.model = self
    self._variables[v.name] = v
    self._elements[v.uuid] = v
    self.notify('elements_added', **{'elements': [v]})

  def add_constant(self, c: Constant):
    c.model = self
    self._constants[c.name] = c
    self._elements[c.uuid] = c
    self.notify('elements_added', **{'elements': [c]})

  def add_function(self, f: Function):
    f.model = self
    if isinstance(f.entry_addr, int):
      self._functions[f.entry_addr] = f
      self._elements[f.uuid] = f
    self.notify('elements_added', **{'elements': [f]})

  def add_type(self, ty: Type):
    ty.model = self
    self._types[ty.name] = ty
    self._elements[ty.uuid] = ty
    self.notify('elements_added', **{'elements': [ty]})

  def get_components_containing(self, el: Element):
    for c in self.root_component.components():
      if el in c:
        yield c

  def get_component(self, qname: QualifiedName) -> Optional[Component]:
    def get_component_helper(parent: Component, index: int):
      for c in parent.operands:
        if isinstance(c, Component):
          if c.name == qname[index]:
            if len(qname) == index - 1:
              return c
            else:
              return get_component_helper(c, index + 1)
      return None

    if qname.is_empty:
      return self._component

    # Find an existing component.
    for c in self._component.operands:
      assert(isinstance(c, Component))
      if c.name == qname[0]:
        if len(qname) == 1:
          return c
        else:
          return get_component_helper(c, 1)

    return None

  def make_leaf_component(self, qname: QualifiedName) -> Component:
    def make_component_helper(parent: Component, index: int):
      for c in parent.operands:
        if isinstance(c, Component):
          if c.name == qname[index]:
            if len(qname) - 1 == index:
              return c
            else:
              return make_component_helper(c, index + 1)

      # Create components according to the qname.
      for child_name in qname[index:]:
        parent.selector = Selector.UNION
        c = Component(None, child_name)
        parent.add_components(c)
        parent = c

      return parent

    if qname.is_empty:
      return self._component

    # Find an existing component.
    for c in self._component.operands:
      assert(isinstance(c, Component))
      if c.name == qname[0]:
        if len(qname) == 1:
          return c
        else:
          return make_component_helper(c, 1)

    # Create components according to the qname.
    top = Component(None, qname[0])
    parent = top
    for child_name in qname[1:]:
      parent.selector = Selector.UNION
      c = Component(None, child_name)
      parent.add_components(c)
      parent = c
    self._component.add_components(top)
    return parent

  def add_abstract_object(self, obj: AbstractObject):
    obj.model = self
    self._abstract_objects.append(obj)
    self.notify('abstract_elements_added', **{'elements': [obj]})

  def add_abstract_flow(self, flow: AbstractFlow):
    flow.model = self
    self._abstract_flows[flow.name] = flow
    self.notify('abstract_elements_added', **{'elements': [flow]})

  def select_elements(self, attr_name, attr_value: Any = None) -> Generator[Union[Element, Component], None, None]:
    for el in self.elements():
      if el.has_attribute(attr_name):
        if attr_value is None or el.get_attribute(attr_name) == attr_value:
          yield el
      if isinstance(el, Function):
        for param in el.parameters:
          if param.has_attribute(attr_name):
            if attr_value is None or param.get_attribute(attr_name) == attr_value:
              yield param
        if el.return_value:
          if el.return_value.has_attribute(attr_name):
            if attr_value is None or el.return_value.get_attribute(attr_name) == attr_value:
              yield el.return_value

  @staticmethod
  def from_dwarf(filename: str, debug_root: Optional[str] = None, name: str = '', logger=None) -> Optional["AnalysisModel"]:
    from elftools.elf.elffile import ELFFile
    from ..io.dwarf_import import import_ELF_DWARF_into_model

    def ELF_has_debug_info(elf_file: ELFFile) -> bool:
      return (
        elf_file.get_section_by_name('.debug_info') is not None
        or elf_file.get_section_by_name('.zdebug_info') is not None
      )

    elf_file = ELFFile(open(filename, 'rb'))
    if ELF_has_debug_info(elf_file) is False:
      return None

    model = AnalysisModel(name=name)
    import_ELF_DWARF_into_model(elf_file, model, debug_root=debug_root, logger=logger)
    return model

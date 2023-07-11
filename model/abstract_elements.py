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

from typing import List, Tuple, Union, Optional, NewType
from uuid import UUID, uuid4
from .observer import Observable
from .attributes import AttributeSet
from .qualified_name import QualifiedName
from .concrete_elements import Element


class AbstractElement(object):
  def __init__(self, model: Optional[Observable] = None, name: Optional[QualifiedName] = None):
    self.uuid: UUID = uuid4()
    self.model = model
    self._name: QualifiedName = name if name else QualifiedName()
    self.attributes: Optional[AttributeSet] = None

  def __eq__(self, rhs: "AbstractElement"):
    return self.uuid == rhs.uuid

  def __hash__(self):
    return hash(self.uuid)

  @property
  def name(self):
    return self._name

  @name.setter
  def name(self, value: QualifiedName):
    if value == self._name:
      return
    old_name = self._name
    self._name = value
    if self.model is not None:
      self.model.notify('entity_renamed', **{'entity': self, 'old_name': old_name})

  def has_attribute(self, key):
    if self.attributes is not None:
      return key in self.attributes
    else:
      return False

  def get_attribute(self, key):
    if self.attributes is not None:
      if key in self.attributes:
        return self.attributes[key]
    return None

  def set_attribute(self, key, value):
    if self.attributes is None:
      self.attributes = AttributeSet()
    self.attributes[key] = value

  def unset_attribute(self, key):
    if self.attributes is not None:
      del self.attributes[key]

  def append_attribute(self, key, value) -> None:
    if self.attributes is None:
      self.attributes = AttributeSet()
    self.attributes.append(key, value)


Scheme = NewType('Scheme', str)

SCHEME_CONSOLE = Scheme('console')
SCHEME_FILESYSTEM = Scheme('file')
SCHEME_NETWORK = Scheme('net')
SCHEME_NETWORK_TCP = Scheme('tcp')
SCHEME_NETWORK_UDP = Scheme('udp')
SCHEME_NETWORK_HTTP = Scheme('http')
SCHEME_PROCESS_HEAP = Scheme('mem')


AbstractType = NewType('AbstractType', str)

ABSTRACT_TYPE_NONE = AbstractType('None')
ABSTRACT_TYPE_HEAP_MEMORY = AbstractType('HeapMemory')
ABSTRACT_TYPE_FILE_OBJECT = AbstractType('FileObject')
ABSTRACT_TYPE_FILE_HANDLE = AbstractType('FileHandle')
ABSTRACT_TYPE_NETWORK_SOCKET = AbstractType('Socket')
ABSTRACT_TYPE_DATASTRUCTURE_LIST = AbstractType('List')
ABSTRACT_TYPE_DATASTRUCTURE_STACK = AbstractType('Stack')
ABSTRACT_TYPE_DATASTRUCTURE_QUEUE = AbstractType('Queue')
ABSTRACT_TYPE_DATASTRUCTURE_TREE = AbstractType('Tree')
ABSTRACT_TYPE_DATASTRUCTURE_GRAPH = AbstractType('Graph')
ABSTRACT_TYPE_DATASTRUCTURE_HASHTABLE = AbstractType('HashTable')
ABSTRACT_TYPE_LINKED = AbstractType('LinkedDataStructure')


class AbstractObject(AbstractElement):
  def __init__(
    self,
    name: QualifiedName,
    abstract_type: AbstractType,
    concrete_element: Optional[Element],
    concrete_allocator: Optional[Element],
    addr: Optional[int] = None
  ):
    super().__init__(name=name)
    self.abstract_type = abstract_type
    self.concrete_element = concrete_element
    self.concrete_allocator = concrete_allocator
    self.addr = addr
    self.context: List[Tuple[Element, Union["AbstractObject", int, str]]] = list()

  def inherit_properties(self, objects: List["AbstractObject"]):
    for attrs in filter(None, map(lambda x: x.attributes, objects)):
      for name, value in attrs.items():
        if not self.has_attribute(name):
          self.set_attribute(name, value)
        else:
          if self.get_attribute(name) != value:
            self.unset_attribute(name)


class AbstractFlow(AbstractElement):
  def __init__(self, source: AbstractObject, sink: AbstractObject):
    self.source = source
    self.sink = sink
    self.capacity: float = 0.0  # Number of bits (ratio of co-domain / domain)
    self.identity: float = 0.0  # Degree of transformation (e.g., edit distance)

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

from enum import Enum, auto
from uuid import uuid4
from itertools import chain
from dataclasses import dataclass
from typing import List, Tuple, Union, Optional, Iterable, Generator
from .touch_flags import TouchFlags
import re


class AccessModifier(Enum):
  UNDEFINED = 0
  PUBLIC = 1
  PRIVATE = 2
  PROTECTED = 2


class Element(object):
  def __init__(self, owner, name: Optional[Union[str, Tuple[str]]]):
    self._uuid = uuid4()
    self._version = 0
    self._owner = owner
    self._name = name

  @property
  def uuid(self):
    return self._uuid

  @property
  def version(self):
    return self._version

  def increment_version(self):
    self._version += 1

  @property
  def owner(self):
    return self._owner

  @property
  def name(self):
    return self._name

  @name.setter
  def name(self, value):
    if value == self._name:
      return
    old_name = self._name
    self._name = value
    if self._owner:
      m = self.module
      if m:
        m.notify('element_renamed', TouchFlags.TOUCHED_NAMES, **{'element': self, 'old_name': old_name})

  @property
  def members(self):
    return ()

  @property
  def module(self):
    c = self.component
    return c.module if c else None

  @property
  def component(self):
    if isinstance(self._owner, Component):
      return self._owner
    elif hasattr(self._owner, 'component'):
      return self._owner.component
    else:
      return None

  @property
  def binary_view(self):
    m = self.module
    return m.binary_view if m else None

  def set_attribute(self, attr_name, attr_value):
    if not hasattr(self, '_attributes'):
      self._attributes = dict()
    self._attributes[attr_name] = attr_value

  def has_attribute(self, attr_name: str) -> bool:
    return hasattr(self, '_attributes') and attr_name in self._attributes

  def get_attribute(self, attr_name):
    if hasattr(self, '_attributes') and attr_name in self._attributes:
      return self._attributes[attr_name]
    else:
      return None


class CompositeType(Enum):
  STRUCT_TYPE = 1
  CLASS_TYPE = 2
  UNION_TYPE = 3
  ENUM_TYPE = 4
  FUNCTION_TYPE = 5
  PTR_TO_MEMBER_TYPE = 6


class ScalarType(Enum):
  BASE_TYPE = 1
  ENUMERATOR_TYPE = 2
  POINTER_TYPE = 3
  REFERENCE_TYPE = 4
  RVALUE_REFERENCE_TYPE = 5
  ARRAY_TYPE = 6


COMPOSITE_KEYWORDS = {
    CompositeType.STRUCT_TYPE: 'struct',
    CompositeType.CLASS_TYPE: 'class',
    CompositeType.UNION_TYPE: 'union',
    CompositeType.ENUM_TYPE: 'enum',
    CompositeType.FUNCTION_TYPE: '',
    CompositeType.PTR_TO_MEMBER_TYPE: ''
}


class Type(Element):
  """A datatype.

  The Type class may contain instances of Type. Thus, the Type class can model
  pointers, structures, and unions.
  """

  def __init__(self, name: Optional[str] = None, offset: Optional[int] = None, size: Optional[int] = None,
               scalar_type: Optional[ScalarType] = None, element: Optional["Type"] = None,
               composite_type: Optional[CompositeType] = None, array_count: Optional[int] = None):
    super().__init__(None, name)
    assert(offset is None or isinstance(offset, int))
    self._offset = offset
    self._byte_size = size
    self._scalar_type = scalar_type
    self._composite_type = composite_type
    self._element = element
    self._members: List[Type] = None
    self._array_count = array_count
    self._is_volatile = False
    self._is_constant = False

  def clone(self):
    cloned_type = Type(name=self._name)
    cloned_type._offset = self._offset
    cloned_type._byte_size = self._byte_size
    cloned_type._scalar_type = self._scalar_type
    cloned_type._composite_type = self._composite_type
    cloned_type._element = self._element
    cloned_type._members = None if self._members is None else list(self._members)
    cloned_type._array_count = self._array_count
    cloned_type._is_volatile = self._is_volatile
    cloned_type._is_constant = self._is_constant
    return cloned_type

  @property
  def is_qualified_type(self) -> bool:
    return self._scalar_type is None and self._composite_type is None and self._name is None

  @property
  def offset(self) -> int:
    return self._offset

  @offset.setter
  def offset(self, k):
    self._offset = k

  @property
  def byte_size(self) -> int:
    return self._byte_size

  @property
  def is_volatile(self) -> bool:
    return self._is_volatile

  @is_volatile.setter
  def is_volatile(self, f):
    self._is_volatile = f

  @property
  def is_constant(self) -> bool:
    return self._is_constant

  @is_constant.setter
  def is_constant(self, f):
    self._is_constant = f

  @property
  def array_count(self) -> Optional[int]:
    return self._array_count

  @property
  def is_alias(self) -> bool:
    return self._composite_type is None and self._name is not None and (self._typestr or self._element_type)

  @property
  def is_base(self) -> bool:
    return self._composite_type is None and self._name is not None and self._typestr is None and self._element_type is None and self._offset is None

  @property
  def composite_type(self) -> CompositeType:
    return self._composite_type

  @composite_type.setter
  def composite_type(self, t: CompositeType):
    self._composite_type = t

  @property
  def scalar_type(self) -> ScalarType:
    return self._scalar_type

  @scalar_type.setter
  def scalar_type(self, t: ScalarType):
    self._scalar_type = t

  @property
  def element(self):
    return self._element

  @property
  def members(self):
    return self._members if self._members is not None else ()
    # return map(lambda m: m if m._name is not None else m._element, self._members) if self._members is not None else []

  def add_member(self, ty: "Type"):
    ty._owner = self
    if self.composite_type == CompositeType.FUNCTION_TYPE:
      assert(ty._element is not None)
    if self._members is None:
      self._members = [ty]
    else:
      self._members.append(ty)

  @property
  def qualified_name(self) -> Optional[str]:
    if isinstance(self._name, str):
      return self._name
    elif isinstance(self._name, tuple):
      return '::'.join(self._name)
    else:
      return None

  def __str__(self):
    return self.as_C()

  INDENT = '  '

  def as_C(self, specifier=False, level=0):
    pad = Type.INDENT*level

    if self._scalar_type == ScalarType.BASE_TYPE:
      return pad + self.qualified_name
    elif self._scalar_type == ScalarType.ENUMERATOR_TYPE:
      return f'{pad}{self.qualified_name}{"" if specifier else f" = {self._offset}"}'
    elif self._scalar_type == ScalarType.POINTER_TYPE:
      if self._name is not None:
        return pad + self.qualified_name
      else:
        return f'{pad}{self._element.as_C(specifier=True)}*'
    elif self._scalar_type == ScalarType.REFERENCE_TYPE:
      return f'{pad}{self._element.as_C(specifier=True)}&'
    elif self._scalar_type == ScalarType.RVALUE_REFERENCE_TYPE:
      return f'{pad}{self._element.as_C(specifier=True)}&&'
    elif self._scalar_type == ScalarType.ARRAY_TYPE:
      element_spec = self._element.as_C(specifier=True)
      dimensions = f'[{self._array_count if self._array_count else ""}]'
      return f'{pad}{element_spec}{dimensions}'

    if specifier == True:
      if self._name is not None:
        keyword = COMPOSITE_KEYWORDS.get(self._composite_type, '')
        if keyword:
          keyword += ' '
        return pad + keyword + self.qualified_name
      elif self._composite_type:
        return self.as_C()
      else:
        s = pad
        s += ' '.join(filter(None, ('const' if self._is_constant else None,
                                    'volatile' if self._is_volatile else None)))
        if self._element is None:
          print(self.__dict__)
          raise Exception(self)
        s += ' '
        s += self._element.as_C(specifier=True)
        return s

    if self._composite_type in [CompositeType.STRUCT_TYPE, CompositeType.CLASS_TYPE, CompositeType.UNION_TYPE]:
      keyword = COMPOSITE_KEYWORDS[self._composite_type]
      begin = pad + ' '.join(filter(None, (keyword, self.qualified_name, '{'))) + '\n'
      fields = ';\n'.join(map(lambda m: indent_lines(self.make_member_line(m, level), Type.INDENT*(level+1)), self.members))
      if fields:
        fields += ';\n'
      end = pad + '}'
      return f'{begin}{fields}{end}'
    elif self._composite_type == CompositeType.ENUM_TYPE:
      begin = pad + ' '.join(filter(None, ('enum', self.qualified_name, '{'))) + '\n'
      fields = ',\n'.join(map(lambda m: indent_lines(m.as_C(level=level+1), Type.INDENT*(level+1)), self._members))
      if fields:
        fields += ',\n'
      end = pad + '}'
      return f'{begin}{fields}{end}'
    elif self._composite_type == CompositeType.FUNCTION_TYPE:
      func_return_type = self._element.as_C(specifier=True)
      func_name = ''
      if self._members:
        func_parameters = ', '.join(map(lambda m: m._element.as_C(specifier=True), self._members))
      else:
        func_parameters = ''
      func_modifiers = ''
      return f'{func_return_type}{func_name}({func_parameters}){func_modifiers}'
    elif self._composite_type == CompositeType.PTR_TO_MEMBER_TYPE:
      containing_type = self._members[0]
      member_type = self._members[1]
      container_name = '::'.join(containing_type.name)
      return f'{container_name}::{member_type.as_C(specifier=True)} *'

    if self._name is not None:
      if self._element is not None:
        return f'{pad}typedef {self._element.as_C(specifier=True)} {self.qualified_name}'
      elif self._composite_type in COMPOSITE_KEYWORDS:
        return f'{pad}{COMPOSITE_KEYWORDS[self._composite_type]} {self.qualified_name}'

    if specifier == False:
      return self.as_C(specifier=True)

    print(self.__dict__)
    assert(False)

  def make_member_line(self, member, level: int) -> str:
    if member._element is None:
      print('Member:', member.__dict__)
      if member._owner:
        print('Owner:', member._owner.__dict__)
    return member._element.as_C(specifier=True, level=level+1) + (' '+member.qualified_name if member._name else '')

  _VOID = None
  _VARIADIC = None

  @staticmethod
  def void():
    if Type._VOID is None:
      Type._VOID = Type(name='void', scalar_type=ScalarType.BASE_TYPE)
    return Type._VOID

  @staticmethod
  def variadic():
    if Type._VARIADIC is None:
      Type._VARIADIC = Type(name='...')
    return Type._VARIADIC


def indent_lines(s, pad):
  return s.replace('\n', f'\n{pad}')


class ExprOp(Enum):
  ADD = auto()
  CFA = auto()  # Canonical frame address
  VAR_FIELD = auto()
  NE = auto()
  GE = auto()
  GT = auto()
  LE = auto()
  LT = auto()
  EQ = auto()
  AND = auto()
  OR = auto()
  MINUS = auto()
  ASHR = auto()
  MUL = auto()
  MOD = auto()
  SHR = auto()
  PLUS_IMM = auto()
  OVER = auto()
  DIV = auto()
  NOT = auto()
  NEG = auto()
  XOR = auto()
  DYNAMIC = 0xfffe
  UNSUPPORTED = 0xffff


class LocationType(Enum):
  STATIC_GLOBAL = 0
  STATIC_LOCAL = 1
  DYNAMIC = 2
  UNSUPPORTED = 3


@dataclass(eq=True, frozen=True)
class Location:
  begin: int
  end: int
  type: LocationType
  expr: Tuple[Union[int, str, ExprOp]]


class Constant(Element):
  def __init__(self, owner = None, name: str = 'constant', type: Optional[Type] = None, value = None):
    super().__init__(owner, name)
    self._type = type
    self._value = value

  @property
  def type(self):
    return self._type

  @property
  def value(self):
    return self._value

  @value.setter
  def value(self, v):
    self._value = v


class Variable(Element):
  def __init__(self, owner = None, name: str = 'variable', start: Optional[int] = None, type: Optional[Type] = None):
    super().__init__(owner, name)
    assert(start is None or isinstance(start, int))
    self._start = start
    self._type = type

  @property
  def start(self):
    return self._start

  @property
  def type(self):
    return self._type


class LocalVariable(Element):
  def __init__(self, function: Optional["Function"] = None, name: str = 'local_variable', type: Optional[Type] = None):
    super().__init__(function, name)
    self._locations: List[Location] = list()
    self._type = type

  def __repr__(self):
    return f'<LocalVariable: {self.name}: {self.type.as_C(specifier=True)}>'

  def clone(self) -> "LocalVariable":
    local_variable_clone = LocalVariable(name=self._name, type=self._type)
    local_variable_clone._locations = list(self._locations)
    return local_variable_clone

  @property
  def function(self):
    return self._owner

  @property
  def type(self):
    return self._type

  @property
  def locations(self):
    return self._locations

  @locations.setter
  def locations(self, loclist: List[Location]):
    self._locations = loclist

  def add_location(self, expr: Location):
    self._locations.append(expr)


def format_type_string_with_name(type_string: str, name: str) -> str:
  # If the type string is an array we have to move the length specifier.
  if type_string[-1] == ']':
    pos = type_string.rfind('[')
    return type_string[:pos] + name + type_string[pos:]
  pos = type_string.find('(*)')
  if pos != -1:
    # NOTE: This may fail because we are not actually parsing the string.
    # This checks that (*) occurs before any other '('.
    if type_string.find('(') >= pos:
      return type_string[:pos] + f'(*{name})' + type_string[pos+3:]
  return f'{type_string} {name}'


class Parameter(Element):
  def __init__(self, function: Optional["Function"] = None, name='parameter', type: Optional[Type] = None):
    super().__init__(function, name)
    self._locations: List[Location] = list()
    self._type = type

  def __repr__(self):
    return f'<Parameter: {self.name}: {self.type}>'

  def clone(self) -> "Parameter":
    parameter_clone = Parameter(name=self._name, type=self._type)
    parameter_clone._locations = list(self._locations)
    return parameter_clone

  @property
  def function(self):
    return self._owner

  @property
  def type(self):
    return self._type

  @property
  def locations(self):
    return self._locations

  def add_location(self, expr: Location):
    self._locations.append(expr)


class Function(Element):
  def __init__(self, owner = None, name: str = 'function', start: Optional[int] = None):
    super().__init__(owner, name)
    self._start = start
    self._parameters: List[Parameter] = list()
    self._frame_base = None
    self._return_type = Type.void()
    self._no_return: bool = False
    self._variables: List[LocalVariable] = list()
    self._constants: Optional[List[Constant]] = None
    self._inlined_functions = None
    self._global_variables = None
    self._access = AccessModifier.UNDEFINED

  def clone(self):
    function_clone = Function(name=self._name, start=self._start)
    function_clone._return_type = self._return_type
    function_clone._access = self._access
    function_clone._no_return = self._no_return
    for p in self._parameters:
      function_clone.add_parameter(p.clone())
    for v in self._variables:
      function_clone.add_variable(v.clone())
    if hasattr(self, '_attributes'):
      function_clone._attributes = dict(self._attributes)
    return function_clone

  def __repr__(self):
    return f'<Function: {self.name}@{hex(self.start)}>'

  @property
  def start(self):
    return self._start

  @property
  def no_return(self) -> bool:
    return self._no_return

  @no_return.setter
  def no_return(self, flag: bool):
    self._no_return = flag

  @property
  def frame_base(self) -> Optional[Union[Location, List[Location]]]:
    return self._frame_base

  @frame_base.setter
  def frame_base(self, loc: Union[Location, List[Location]]):
    self._frame_base = loc

  @property
  def return_type(self) -> str:
    return self._return_type

  @return_type.setter
  def return_type(self, type_: "Type"):
    self._return_type = type_

  @property
  def prototype(self) -> str:
    suffix = ' __noreturn' if self._no_return else ''
    return f'{self._return_type.as_C(specifier=True)} {self._name}({", ".join(map(lambda p: format_type_string_with_name(p.type_string, p.name), self._parameters))}){suffix}'

  @property
  def access(self):
    if self._access is not None:
      return self._access
    if self.binary_view:
      self._access = AccessModifier.PRIVATE
      local = set(self._component.function_starts())
      for xref in self.binary_view.get_code_refs(self._start):
        if xref.function.start not in local:
          self._access = AccessModifier.PUBLIC
          break
      return self._access
    return AccessModifier.UNDEFINED

  @property
  def variables(self):
    return self._variables

  def add_variable(self, variable: LocalVariable):
    variable._owner = self
    self._variables.append(variable)

  @property
  def constants(self):
    return self._constants if self._constants is not None else ()

  def add_constant(self, constant: Constant):
    constant._owner = self
    if self._constants is None:
      self._constants = []
    self._constants.append(constant)

  @property
  def parameters(self):
    return self._parameters

  @property
  def inlined_functions(self) -> Iterable["Function"]:
    return self._inlined_functions if self._inlined_functions is not None else ()

  @property
  def global_variables(self) -> Iterable[Variable]:
    return self._global_variables if self._global_variables is not None else()

  def add_parameter(self, parameter: Parameter):
    parameter._owner = self
    self._parameters.append(parameter)

  def add_inlined_function(self, inlined_function: "Function"):
    inlined_function._owner = self
    if self._inlined_functions is None:
      self._inlined_functions = []
    self._inlined_functions.append(inlined_function)

  def add_global_variable_reference(self, v: Variable):
    if self._global_variables is None:
      self._global_variables = []
    self._global_variables.append(v)

  @property
  def members(self):
    return chain(self._parameters, self._variables)

  def traverse_functions(self) -> Generator["Function", None, None]:
    yield self
    for child in self.inlined_functions:
      for f in child.traverse_functions():
        yield f


class ImportedFunction(Element):
  def __init__(self, owner = None, name: str = 'function', start: Optional[int] = None):
    super().__init__(owner, name)
    self._start = start

  def __repr__(self):
    if self.start is not None:
      return f'<ImportedFunction: {self.name}@{hex(self.start)}>'
    else:
      return f'<ImportedFunction: {self.name}>'

  @property
  def start(self):
    return self._start


class ImportedVariable(Element):
  def __init__(self, owner = None, name: str = 'variable', start: Optional[int] = None, type_: Optional[Type] = None):
    super().__init__(owner, name)
    self._start = start
    self._type = type_

  def __repr__(self):
    if self.start is not None:
      return f'<ImportedVariable: {self.name}@{hex(self.start)}>'
    else:
      return f'<ImportedVariable: {self.name}>'

  @property
  def start(self):
    return self._start

  @property
  def type(self):
    return self._type


class ImportedModule(Element):
  def __init__(self, component: Optional["Component"] = None, name='imported_module'):
    super().__init__(component, name)
    self._functions: List[ImportedFunction] = list()
    self._variables: List[ImportedVariable] = list()

  @property
  def functions(self):
    return self._functions

  @property
  def variables(self):
    return self._variables

  def add_functions(self, functions: Union[ImportedFunction, Iterable[ImportedFunction]]):
    if isinstance(functions, ImportedFunction):
      functions = [functions]
    for fn in functions:
      fn._owner = self
    self._functions.extend(functions)
    m = self.module
    if m:
      m.notify('elements_added', TouchFlags.TOUCHED_TYPES, **{'elements': list(functions)})

  def add_variables(self, variables: Union[Variable, Iterable[ImportedVariable]]):
    if isinstance(variables, ImportedVariable):
      variables = [variables]
    for v in variables:
      v._owner = self
    self._variables.extend(variables)
    m = self.module
    if m:
      m.notify('elements_added', TouchFlags.TOUCHED_TYPES, **{'elements': list(variables)})

  @property
  def members(self):
    return chain(self._functions, self._variables)


class FactorStatus(Enum):
  MAYBE_FACTORED = 1
  FACTORED = 2
  NOT_FACTORED = 4


class ComponentOrigin(Enum):
  BINARY = 0
  SOURCE = 1


class Component(object):
  def __init__(self, name: Optional[str] = None):
    self._module = None
    self._uuid = uuid4()
    self._name = name
    self._types = list()
    self._functions = list()
    self._variables = list()
    self._constants = list()
    self._imported_modules = list()
    self._origin = ComponentOrigin.BINARY

  def __repr__(self):
    if self.name is None:
      n = self._functions[0].name if len(self._functions) == 1 else '<unnamed component>, '
    else:
      n = f'{self.name}, '
    return f'<Component: {n}{len(self._functions)} functions, {len(self._variables)} variables>'

  def __len__(self):
    return len(self._functions) + len(self._variables)

  @property
  def module(self):
    return self._module

  @module.setter
  def module(self, module):
    module.add_component(self)

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
      if self._module:
        self._module.notify('component_renamed', TouchFlags.TOUCHED_NAMES, **{'component': self, 'old_name': old_name})

  @property
  def start(self):
    if self._functions:
      return min(self.function_starts())
    else:
      return None

  @property
  def binary_view(self):
    if self._module:
      return self._module.binary_view
    else:
      return None

  @property
  def types(self):
    return self._types

  @property
  def imported_modules(self):
    return self._imported_modules

  @property
  def functions(self):
    return self._functions

  @property
  def variables(self):
    return self._variables

  @property
  def constants(self):
    return self._constants

  @property
  def origin(self) -> ComponentOrigin:
    return self._origin

  @origin.setter
  def origin(self, origin: ComponentOrigin):
    self._origin = origin

  def get_function_at(self, start: int) -> Optional[Function]:
    for fn in self._functions:
      if start == fn.start:
        return fn
    return None

  def add_imported_modules(self, imported_modules: Union[ImportedModule, Iterable[ImportedModule]]):
    if isinstance(imported_modules, ImportedModule):
      imported_modules = [imported_modules]
    self._imported_modules.extend(map(self._own, imported_modules))
    m = self.module
    if m:
      m.notify('elements_added', TouchFlags.TOUCHED_IMPORTS, **{'elements': list(imported_modules)})

  def add_functions(self, functions: Union[Function, Iterable[Function]]):
    if isinstance(functions, Function):
      functions = [functions]
    self._functions.extend(map(self._own, functions))
    m = self.module
    if m:
      m.notify('elements_added', TouchFlags.TOUCHED_FUNCTION_SET, **{'elements': list(functions)})

  def remove_functions(self, functions: Union[Function, Iterable[Function]]):
    if isinstance(functions, Function):
      functions = [functions]
    functions = list(functions)
    for f in functions:
      self._functions.remove(f)
    m = self.module
    if m:
      m.notify('elements_removed', TouchFlags.TOUCHED_FUNCTION_SET, **{'elements': list(functions)})
    return functions

  def add_variables(self, variables: Union[Variable, Iterable[Variable]]):
    if isinstance(variables, Variable):
      variables = [variables]
    self._variables.extend(map(self._own, variables))
    m = self.module
    if m:
      m.notify('elements_added', TouchFlags.TOUCHED_VARIABLES, **{'elements': list(variables)})

  def add_constants(self, constants: Union[Constant, Iterable[Constant]]):
    if isinstance(constants, Constant):
      constants = [constants]
    self._constants.extend(map(self._own, constants))
    m = self.module
    if m:
      m.notify('elements_added', TouchFlags.TOUCHED_VARIABLES, **{'elements': list(constants)})

  def add_types(self, types: Union[Type, Iterable[Type]]):
    if isinstance(types, Type):
      types = [types]
    self._types.extend(map(self._own, types))
    m = self.module
    if m:
      m.notify('elements_added', TouchFlags.TOUCHED_TYPES, **{'elements': list(types)})

  def get_import_at(self, start):
    for i in self._imports:
      if i.start == start:
        return i
    return None

  def function_starts(self):
    return map(lambda fn: fn.start, self._functions)

  @property
  def members(self):
    return chain(self._types, self._variables, self._constants, self._functions, self._imported_modules)

  def traverse_members(self):
    for m in self.members:
      yield m
      for el in self.traverse_members_helper(m):
        yield el

  def traverse_members_helper(self, el):
    for m in el.members:
      yield m
      for x in self.traverse_members_helper(m):
        yield x

  def siblings(self):
    if self._module is not None:
      for child in self._module.children():
        if child != self:
          yield child

  def _own(self, element):
    element._owner = self
    return element

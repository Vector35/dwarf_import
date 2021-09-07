# Copyright(c) 2021 Vector 35 Inc
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
from dataclasses import dataclass
from typing import List, Optional, Any, Iterable, Union, Tuple, MutableMapping
from itertools import chain
from uuid import uuid4, UUID
from enum import Enum
from .qualified_name import QualifiedName
from .locations import Location
from .attributes import AttributeSet
from .observer import Observable


class Element(object):
  def __init__(self, model: Optional[Observable] = None, name: Optional[QualifiedName] = None):
    self.uuid: UUID = uuid4()
    self.version: int = 0
    self.model: Optional[Observable] = model
    self._name: QualifiedName = name if name else QualifiedName()
    self.attributes: Optional[AttributeSet] = None

  def __eq__(self, rhs: "Element"):
    return self.uuid == rhs.uuid

  def __hash__(self):
    return hash(self.uuid)

  def increment_version(self):
    self.version += 1

  @property
  def name(self):
    return self._name

  @name.setter
  def name(self, value: QualifiedName):
    if value == self._name:
      return
    self._name = value

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

  def append_attribute(self, key, value) -> None:
    if self.attributes is None:
      self.attributes = AttributeSet()
    self.attributes.append(key, value)


class Type(Element):
  def __init__(self, name: Optional[QualifiedName] = None, byte_size: Optional[int] = 0):
    super().__init__(name=name)
    self.byte_size: Optional[int] = byte_size

  def is_equivalent(self, ty: "Type") -> bool:
    if type(self) != type(ty):
      return False
    return self.byte_size == ty.byte_size

  def has_ancestor_class(self, typeclass) -> bool:
    return isinstance(self, typeclass)

  def strip_modifiers(self) -> "Type":
    return self


class BaseType(Type):
  def __init__(self, name: str, byte_size: Optional[int]):
    super().__init__(name=QualifiedName(name), byte_size=byte_size)
    assert(self.byte_size is None or isinstance(self.byte_size, int))

  def __repr__(self):
    return self.name[0]

  def __str__(self):
    return self.name[0]

  def is_equivalent(self, ty: "Type") -> bool:
    if type(self) != type(ty):
      return False
    return self.byte_size == ty.byte_size and self.name == ty.name

  @staticmethod
  def int(byte_size: int) -> "Type":
    return BaseType(name=f'int{byte_size*8}_t', byte_size=byte_size)


class VoidType(BaseType):
  def __init__(self):
    super().__init__('void', 0)
    self.uuid = UUID('00000000000000000000000000000000')


VOID = VoidType()


class VariadicType(Type):
  def __init__(self):
    super().__init__()
    self.uuid = UUID('00000000000000000000000000000001')

  def __repr__(self):
    return '...'

  def __str__(self):
    return '...'


VARIADIC = VariadicType()


class AliasType(Type):
  def __init__(self, name: QualifiedName, type: Type):
    super().__init__(name=name)
    assert(isinstance(type, Type))
    self.type = type

  def __repr__(self):
    if isinstance(self.type, AliasType):
      return f'typedef {str(self.type)} {str(self.name)}'
    else:
      return f'typedef {self.type.__repr__()} {str(self.name)}'

  def __str__(self):
    return str(self.name)

  def is_equivalent(self, ty: "Type") -> bool:
    if type(self) != type(ty):
      return False
    assert(isinstance(ty, AliasType))
    return self.byte_size == ty.byte_size and self.type.is_equivalent(ty.type)

  def is_alias_for_type(self, type_class) -> bool:
    if isinstance(self.type, type_class):
      return True
    if isinstance(self.type, AliasType):
      return self.type.is_alias_for_type(type_class)
    return False

  def resolve_alias(self) -> Type:
    if not isinstance(self.type, AliasType):
      return self.type
    return self.type.resolve_alias()

  def has_ancestor_class(self, typeclass) -> bool:
    if typeclass == AliasType:
      return True
    return self.type.has_ancestor_class(typeclass)

  def strip_modifiers(self) -> Type:
    return self.type.strip_modifiers()


class PointerType(Type):
  def __init__(self, byte_size: Optional[int], target_type: Type = VOID, nullable: bool = True):
    super().__init__(byte_size=byte_size)
    self.target_type = target_type
    self.nullable = nullable

  def __repr__(self):
    if self.nullable is True:
      return f'{str(self.target_type)} *'
    else:
      return f'{str(self.target_type)} &'

  def __str__(self):
    if self.nullable is True:
      return f'{str(self.target_type)} *'
    else:
      return f'{str(self.target_type)} &'

  def is_equivalent(self, ty: Type) -> bool:
    if type(self) != type(ty):
      return False
    assert(isinstance(ty, PointerType))
    return (
        self.byte_size == ty.byte_size
        and self.nullable == ty.nullable
        and self.target_type.is_equivalent(ty.target_type)
    )

  def has_ancestor_class(self, typeclass) -> bool:
    if typeclass == PointerType:
      return True
    return self.target_type.has_ancestor_class(typeclass)

  def strip_modifiers(self) -> Type:
    return self.target_type.strip_modifiers()


VOID_PTR = PointerType(None, target_type=VOID)


class ConstType(Type):
  def __init__(self, type: Type):
    super().__init__()
    self.type = type
    assert(self.name.is_empty)

  def __repr__(self) -> str:
    return f'const {self.type.__repr__()}'

  def __str__(self):
    return f'{self.type} const'

  def has_ancestor_class(self, typeclass) -> bool:
    if typeclass == ConstType:
      return True
    return self.type.has_ancestor_class(typeclass)

  def is_equivalent(self, ty: "Type") -> bool:
    if type(self) != type(ty):
      return False
    assert(isinstance(ty, ConstType))
    return (
        self.byte_size == ty.byte_size and
        self.type.is_equivalent(ty.type)
    )

  def strip_modifiers(self) -> Type:
    return self.type.strip_modifiers()


class VolatileType(Type):
  def __init__(self, type: Type):
    super().__init__()
    self.type = type
    assert(self.name.is_empty)

  def __repr__(self) -> str:
    return f'volatile {self.type.__repr__()}'

  def __str__(self):
    return f'{self.type} volatile'

  def has_ancestor_class(self, typeclass) -> bool:
    if typeclass == VolatileType:
      return True
    return self.type.has_ancestor_class(typeclass)

  def is_equivalent(self, ty: "Type") -> bool:
    if type(self) != type(ty):
      return False
    assert(isinstance(ty, VolatileType))
    return (
        self.byte_size == ty.byte_size and
        self.type.is_equivalent(ty.type)
    )

  def strip_modifiers(self) -> Type:
    return self.type.strip_modifiers()


class ArrayType(Type):
  def __init__(self, element_type: Type, count: int, name: Optional[QualifiedName] = None):
    super().__init__(name=name)
    self.element_type = element_type
    self.count = count

  def __str__(self):
    if self.count == 0:
      return f'{str(self.element_type)} []'
    else:
      return f'{str(self.element_type)} [{self.count}]'

  def has_ancestor_class(self, typeclass) -> bool:
    if typeclass == ArrayType:
      return True
    return self.element_type.has_ancestor_class(typeclass)

  def is_equivalent(self, ty: "Type") -> bool:
    if type(self) != type(ty):
      return False
    assert(isinstance(ty, ArrayType))
    return (
        self.byte_size == ty.byte_size and
        self.count == ty.count and
        self.element_type.is_equivalent(ty.element_type)
    )


class StringType(Type):
  def __init__(self, char_size: int, is_null_terminated: bool, byte_size: int):
    super().__init__(byte_size=byte_size)
    self.char_size = char_size
    self.is_null_terminated = is_null_terminated

  def is_equivalent(self, ty: "Type") -> bool:
    if type(self) != type(ty):
      return False
    assert(isinstance(ty, StringType))
    return (
        self.byte_size == ty.byte_size and
        self.char_size == ty.char_size and
        self.is_null_terminated == ty.is_null_terminated
    )


class Constant(Element):
  def __init__(self, name: QualifiedName, type: Optional[Type], value: Any):
    super().__init__(name=name)
    self.type = type
    self.value: Any = None


class Variable(Element):
  def __init__(self, name: QualifiedName, addr: Optional[int] = None, type: Optional[Type] = VOID, value: Any = None):
    super().__init__(name=name)
    self.addr = addr
    self.type = type
    self.initial_value = value


class AccessSpecifier(Enum):
  UNDEFINED = 0
  PUBLIC = 1
  PRIVATE = 2
  PROTECTED = 2


class MemberPermissions(Enum):
  READ_ONLY = 0
  READ_WRITE = 1


@dataclass
class Member:
  accessibility: AccessSpecifier = AccessSpecifier.PUBLIC
  permissions: MemberPermissions = MemberPermissions.READ_ONLY


@dataclass
class MemberType(Member):
  type: Type = VOID

  def __repr__(self):
    return self.type.__repr__()

  def __str__(self) -> str:
    return str(self.type)


@dataclass
class MemberConstant(Member):
  constant: Constant = None  # type: ignore

  def __repr__(self):
    return self.constant.__repr__()

  def __str__(self) -> str:
    return str(self.constant)


@dataclass
class MemberFunction(Member):
  function: "Function" = None  # type: ignore
  read_only: bool = False

  def __repr__(self):
    if self.read_only:
      return f'{self.function.__repr__()} const'
    else:
      return self.function.__repr__()

  def __str__(self) -> str:
    return self.function.__str__()


class Field(Element):
  def __init__(self, name: Optional[str], offset: int, type: Type):
    super().__init__(name=QualifiedName(name) if name else QualifiedName())
    self.offset = offset
    self.type = type

  @property
  def local_name(self) -> str:
    if len(self.name) == 0:
      return ''
    else:
      return self.name[-1]

  @property
  def size(self) -> Optional[int]:
    # if self.type.byte_size is None:
    #     raise Exception('Field has no size')
    return self.type.byte_size

  @property
  def storage(self) -> Tuple[int, int]:
    sz = self.size
    return (self.offset, sz if sz else 0)


@dataclass
class MemberField(Member):
  field: Field = None  # type: ignore

  def __repr__(self):
    if self.field.local_name == '':
      if isinstance(self.field.type, CompositeType):
        return self.field.type.__repr__()
      assert(isinstance(self.field.type, AliasType))
      cty = self.field.type.resolve_alias()
      return cty.__repr__()
    else:
      return f'{str(self.field.type)} {self.field.local_name}'

  def __str__(self) -> str:
    assert(isinstance(self.field.local_name, str))
    return self.field.local_name


class CompositeLayout(Enum):
  DISJOINT = 0
  UNION = 1


class CompositePolicy(object):
  def __init__(self, name: str, default_access: AccessSpecifier, layout_type: CompositeLayout = CompositeLayout.DISJOINT):
    self.name = name
    self.default_access = default_access
    self.layout_type = layout_type

  def add_field(self, composite: "CompositeType", field):
    field.name = composite.name.concat(field.name)
    composite.members.append(MemberField(accessibility=self.default_access, field=field))

  def add_unnamed_field(self, composite: "CompositeType", field: Field):
    def is_composite_like(ty: Type) -> bool:
      if not isinstance(ty, CompositeType):
        if not (isinstance(ty, AliasType) and ty.is_alias_for_type(CompositeType)):
          return False
      return True

    if not is_composite_like(field.type):
      raise Exception('Invalid type for field')
    if field.type == composite:
      raise Exception('Invalid circular definition')

    field.name = composite.name.concat('')
    composite.members.append(MemberField(accessibility=self.default_access, field=field))


CLASS_COMPOSITE_POLICY = CompositePolicy('class', AccessSpecifier.PRIVATE)
STRUCT_COMPOSITE_POLICY = CompositePolicy('struct', AccessSpecifier.PUBLIC)
UNION_COMPOSITE_POLICY = CompositePolicy('union', AccessSpecifier.PUBLIC, layout_type=CompositeLayout.UNION)


class CompositeType(Type):
  def __init__(self, policy: CompositePolicy, name: Optional[QualifiedName], byte_size: Optional[int] = None):
    super().__init__(name=name, byte_size=byte_size)
    self.policy = policy
    self.members: List[Member] = list()
    self.storage_index: MutableMapping[Tuple[int, int], MemberField] = dict()

  def __repr__(self) -> str:
    # TODO: fields vs. non-fields
    # TODO: sort fields by offset
    # TODO: check for non-overlapping fields
    member_types = (m.__repr__() for m in self.types())
    member_constants = (m.__repr__() for m in self.constants())
    member_functions = (f.__repr__() for f in self.functions())
    member_fields = (f.__repr__() for f in sorted(self.fields(), key=lambda mf: mf.field.offset))
    decls = ';\n'.join(chain(member_types, member_constants, member_functions, member_fields, ''))
    body = '\n    ' + decls.replace('\n', '\n    ') + ';' if decls else ''
    return f'{self.policy.name} {str(self.name)}\n{{{body}\n}}'

  def __str__(self) -> str:
    return f'{self.policy.name} {str(self.name)}'

  def __len__(self) -> int:
    return len(self.members)

  def types(self) -> Iterable[MemberType]:
    return filter(lambda m: isinstance(m, MemberType), self.members)  # type: ignore

  def constants(self) -> Iterable[MemberConstant]:
    return filter(lambda m: isinstance(m, MemberConstant), self.members)  # type: ignore

  def functions(self) -> Iterable[MemberFunction]:
    return filter(lambda m: isinstance(m, MemberFunction), self.members)  # type: ignore

  def fields(self) -> Iterable[MemberField]:
    return filter(lambda m: isinstance(m, MemberField), self.members)  # type: ignore

  def add_field(self, field: Field):
    self.policy.add_field(self, field)

  def add_unnamed_field(self, field: Field):
    self.policy.add_unnamed_field(self, field)

  def add_constant(self, local_name: str, c: Constant):
    c.name = self.name.concat(local_name)
    self.members.append(MemberConstant(self.policy.default_access, constant=c))

  def add_function(self, fn: "Function", perms: MemberPermissions = MemberPermissions.READ_WRITE):
    fn.name = self.name.concat(fn.name[-1])
    self.members.append(MemberFunction(self.policy.default_access, perms, fn))

  def update(self, rhs: "CompositeType") -> bool:
    if self.policy != rhs.policy:
      return False
    for m in rhs.members:
      if not self._contains_congruent_member(m):
        self._add_member(m)
    return True

  def _add_member(self, m: Member):
    if isinstance(m, MemberFunction):
      self.add_function(m.function, m.permissions)
    elif isinstance(m, MemberConstant):
      self.add_constant(m.constant.name[-1], m.constant)
    elif isinstance(m, MemberField):
      if self.is_storage_available(m.field.storage):
        self.add_field(m.field)
    elif isinstance(m, MemberType):
      self.members.append(m)

  def is_storage_available(self, storage: Tuple[int, int]) -> bool:
    if storage in self.storage_index:
      return False
    return True

  def _contains_congruent_member(self, m: Member):
    for existing_member in self.members:
      if type(existing_member) != type(m):
        continue
      if isinstance(m, MemberFunction):
        assert(isinstance(existing_member, MemberFunction))
        if (
            m.function.name == existing_member.function.name and
            m.read_only == existing_member.read_only
        ):
          return True
      elif isinstance(m, MemberConstant):
        assert(isinstance(existing_member, MemberConstant))
        raise NotImplementedError
      elif isinstance(m, MemberField):
        assert(isinstance(existing_member, MemberField))
        if (
            m.field.name == existing_member.field.name and
            m.field.type.is_equivalent(existing_member.field.type)
        ):
          return True
      elif isinstance(m, MemberType):
        assert(isinstance(existing_member, MemberType))
        raise NotImplementedError

    return False

  def is_equivalent(self, ty: "Type") -> bool:
    if type(self) != type(ty):
      return False
    assert(isinstance(ty, CompositeType))
    return (
        self.byte_size == ty.byte_size and
        self.policy.name == ty.policy.name and
        self.name == ty.name
    )


class ClassType(CompositeType):
  def __init__(self, name: Optional[QualifiedName] = None, byte_size: Optional[int] = None):
    super().__init__(CLASS_COMPOSITE_POLICY, name, byte_size)

  def __repr__(self) -> str:
    return super().__repr__()


class StructType(CompositeType):
  def __init__(self, name: Optional[QualifiedName] = None, byte_size: Optional[int] = None):
    super().__init__(STRUCT_COMPOSITE_POLICY, name, byte_size)

  def __repr__(self) -> str:
    return super().__repr__()


class UnionType(CompositeType):
  def __init__(self, name: Optional[QualifiedName] = None, byte_size: Optional[int] = None):
    super().__init__(UNION_COMPOSITE_POLICY, name, byte_size)

  def __repr__(self) -> str:
    return super().__repr__()

  def is_storage_available(self, storage: Tuple[int, int]) -> bool:
    return True


@dataclass
class Enumerator:
  label: str
  value: Any

  def __repr__(self):
    return f'{self.label} = {str(self.value)}'

  def __str__(self) -> str:
    return self.label


class EnumType(Type):
  def __init__(self, name: Optional[QualifiedName], byte_size: int):
    super().__init__(name=name, byte_size=byte_size)
    self.enumerators: List[Enumerator] = list()

  def __repr__(self):
    items = ';\n'.join((e.__repr__() for e in self.enumerators))
    body = '\n    ' + items.replace('\n', '\n    ') + ';' if items else ''
    return f'enum {str(self.name)}\n{{{body}\n}}'

  def __str__(self) -> str:
    return f'enum {str(self.name)}'

  def add_enumerator(self, e: Enumerator):
    self.enumerators.append(e)

  def is_equivalent(self, ty: Type) -> bool:
    if type(self) != type(ty):
      return False
    assert(isinstance(ty, EnumType))
    return (
        self.byte_size == ty.byte_size and
        self.enumerators == ty.enumerators
    )


class FunctionType(Type):
  def __init__(self, name: QualifiedName, return_type: Optional[Type]):
    super().__init__()
    self.parameters: List[Type] = []
    self.return_type = return_type
    self.no_return: bool = False

  def __str__(self) -> str:
    params = ', '.join([str(p) for p in self.parameters])
    return f'{self.return_type} {str(self.name)}({params})'

  def is_equivalent(self, ty: Type) -> bool:
    if type(self) != type(ty):
      return False
    assert(isinstance(ty, FunctionType))
    if self.return_type is None or ty.return_type is None:
      return False
    for pi, qi in zip(self.parameters, ty.parameters):
      if not pi.is_equivalent(qi):
        return False
    return (
        self.byte_size == ty.byte_size and
        self.return_type.is_equivalent(ty.return_type)
    )


class PointerToMemberType(Type):
  def __init__(self, name: QualifiedName, container: CompositeType, target: Union[Type, MemberField]):
    super().__init__(name=name)
    self.container = container
    self.target = target

  @property
  def target_type(self) -> Type:
    if isinstance(self.target, Type):
      return self.target
    else:
      return self.target.field.type


def type_refers_to(ty: Type, target: Type):
  if isinstance(ty, ConstType):
    return type_refers_to(ty.type, target)
  elif isinstance(ty, VolatileType):
    return type_refers_to(ty.type, target)
  elif isinstance(ty, AliasType):
    return type_refers_to(ty.type, target)
  elif isinstance(ty, PointerType):
    return ty.target_type is target
  else:
    return False


def get_referenced_type(ty: Type):
  if isinstance(ty, ConstType):
    return get_referenced_type(ty.type)
  elif isinstance(ty, VolatileType):
    return get_referenced_type(ty.type)
  elif isinstance(ty, AliasType):
    return get_referenced_type(ty.type)
  elif isinstance(ty, PointerType):
    return get_referenced_type(ty.target_type)
  elif isinstance(ty, CompositeType):
    return ty
  else:
    return None


class Parameter(Element):
  def __init__(self, function: "Function", name: Optional[str], type: Type):
    super().__init__(name=QualifiedName(*function.name, name) if name else None)
    self._function = function
    self.model = function.model
    self.type = type
    self.locations: List[Location] = []

  def __repr__(self) -> str:
    return f'{self.local_name}: {str(self.type)}'

  @property
  def local_name(self) -> str:
    if self.name:
      return self.name[-1]
    else:
      return ''

  @property
  def function(self) -> "Function":
    return self._function

  @function.setter
  def function(self, fn: "Function"):
    self._function = fn
    self.model = fn.model

  def add_location(self, loc: Location):
    self.locations.append(loc)


class ReturnValue(Element):
  def __init__(self, function: "Function", type: Type):
    super().__init__()
    self._function = function
    self.model = function.model
    self.type = type

  @property
  def function(self) -> "Function":
    return self._function

  @function.setter
  def function(self, fn: "Function"):
    self._function = fn
    self.model = fn.model


@dataclass
class VariableStorage:
  storage_type: int
  storage_id: int


class LocalVariable(Element):
  def __init__(self, function: "Function", name: str, type: Type, storage=None):
    super().__init__(name=QualifiedName(*function.name, name))
    self._function = function
    self.model = function.model
    self.type = type
    self.locations: List[Location] = []
    self.storage: List[VariableStorage] = storage if storage else []

  @property
  def local_name(self) -> str:
    if self.name:
      return self.name[-1]
    else:
      return ''

  @property
  def function(self) -> "Function":
    return self._function

  @function.setter
  def function(self, fn: "Function"):
    self._function = fn
    self.model = fn.model

  def add_location(self, loc: Location):
    self.locations.append(loc)


class LocalConstant(Element):
  def __init__(self, function: "Function", name: str, type: Type, value: Any = None):
    super().__init__(name=QualifiedName(*function.name, name))
    self._function = function
    self.model = function.model
    self.type = type
    self.value = value

  @property
  def local_name(self) -> str:
    if self.name:
      return self.name[-1]
    else:
      return ''

  @property
  def function(self) -> "Function":
    return self._function

  @function.setter
  def function(self, fn: "Function"):
    self._function = fn
    self.model = fn.model


class Function(Element):
  def __init__(self, name: Optional[QualifiedName], entry_addr: Optional[int] = None):
    super().__init__(name=name)
    self.entry_addr = entry_addr
    self._parameters: List[Parameter] = list()
    self._return_value: Optional[ReturnValue] = None
    self.variables: Optional[List[LocalVariable]] = None
    self.constants: Optional[List[LocalConstant]] = None
    self.inlined_functions: Optional[List["Function"]] = None
    self.no_return: bool = False
    self.frame_base: Any = None
    self.has_definition: bool = True
    self.is_inlined: bool = False
    self.ranges: Optional[List[Tuple[int, int]]] = None

  def __repr__(self) -> str:
    if self._return_value is None:
      return f'void {str(self.name)}({self._parameters})'
    else:
      return f'{str(self._return_value.type)} {str(self.name)}({self._parameters})'

  def __str__(self) -> str:
    return str(self.name)

  @property
  def return_value(self):
    return self._return_value

  def set_return_type(self, ty: Type):
    if self._return_value is None:
      self._return_value = ReturnValue(self, ty)
    else:
      self._return_value.type = ty

  @property
  def variadic(self) -> bool:
    return any(map(lambda p: isinstance(p.type, VariadicType), self._parameters))

  @property
  def is_constructor(self) -> bool:
    return len(self.name) >= 2 and self.name[-1] == self.name[-2]

  @property
  def is_destructor(self) -> bool:
    return not self.name.is_anonymous and self.name[-1][0] == '~'

  @property
  def lowerbound(self) -> int:
    if self.ranges:
      return min(map(lambda r: r[0], self.ranges))
    return sys.maxsize

  @property
  def upperbound(self) -> int:
    if self.ranges:
      return max(map(lambda r: r[1], self.ranges))
    return 0

  @property
  def parameters(self):
    return tuple(self._parameters)

  def append_parameter(self, name: Optional[str], type: Type):
    p = Parameter(self, name, type)
    self._parameters.append(p)
    return p

  def add_variable(self, name: str, ty: Type):
    v = LocalVariable(self, name, ty)
    if self.variables is None:
      self.variables = list()
    self.variables.append(v)
    return v

  def add_constant(self, name: str, ty: Type, value: Any):
    c = LocalConstant(self, name, ty, value)
    if self.constants is None:
      self.constants = list()
    self.constants.append(c)

  def add_inlined_function(self, inlined_fn: "Function"):
    if self.inlined_functions is None:
      self.inlined_functions = list()
    self.inlined_functions.append(inlined_fn)

  def iter_variables(self):
    if self.variables is not None:
      for v in self.variables:
        yield v

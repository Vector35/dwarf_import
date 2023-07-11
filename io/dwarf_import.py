# Copyright(c) 2020-2023 Vector 35 Inc
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
# Copyright (c) 2020 Vector 35 Inc

import os
import sys
import elftools
import elftools.dwarf.ranges
import elftools.dwarf.constants as dw
import logging
from enum import Enum, auto
from collections import defaultdict
from itertools import tee
from typing import MutableMapping, Iterator, List, Set, Optional, Union, Tuple, Any, ValuesView
from elftools.elf.elffile import ELFFile, SymbolTableSection
from elftools.dwarf.compileunit import CompileUnit
from .dwarf_expr import LocExprParser
from elftools.dwarf.die import AttributeValue, DIE
from elftools.dwarf.locationlists import LocationEntry, BaseAddressEntry
from ..model import QualifiedName, Component, AnalysisModel
from ..model.locations import ExprOp, Location, LocationType
from ..model.concrete_elements import (
  Element,
  Type,
  Constant,
  Variable,
  Function,
  BaseType, AliasType, ArrayType, PointerType,
  CompositeType, ConstType, VolatileType, StructType, ClassType, UnionType,
  EnumType, Enumerator, FunctionType, StringType, PointerToMemberType,
  LocalVariable,
  Parameter,
  Field,
  VOID, VOID_PTR, VARIADIC
)


class Language(Enum):
  C89 = dw.DW_LANG_C89
  C = dw.DW_LANG_C
  Ada83 = dw.DW_LANG_Ada83
  C_plus_plus = dw.DW_LANG_C_plus_plus
  Cobol74 = dw.DW_LANG_Cobol74
  Cobol85 = dw.DW_LANG_Cobol85
  Fortran77 = dw.DW_LANG_Fortran77
  Fortran90 = dw.DW_LANG_Fortran90
  Pascal83 = dw.DW_LANG_Pascal83
  Modula2 = dw.DW_LANG_Modula2
  Java = dw.DW_LANG_Java
  C99 = dw.DW_LANG_C99
  Ada95 = dw.DW_LANG_Ada95
  Fortran95 = dw.DW_LANG_Fortran95
  PLI = dw.DW_LANG_PLI
  ObjC = dw.DW_LANG_ObjC
  ObjC_plus_plus = dw.DW_LANG_ObjC_plus_plus
  UPC = dw.DW_LANG_UPC
  D = dw.DW_LANG_D
  Python = dw.DW_LANG_Python
  OpenCL = dw.DW_LANG_OpenCL
  Go = dw.DW_LANG_Go
  Modula3 = dw.DW_LANG_Modula3
  Haskell = dw.DW_LANG_Haskell
  C_plus_plus_03 = dw.DW_LANG_C_plus_plus_03
  C_plus_plus_11 = dw.DW_LANG_C_plus_plus_11
  OCaml = dw.DW_LANG_OCaml
  Rust = dw.DW_LANG_Rust
  C11 = dw.DW_LANG_C11
  Swift = dw.DW_LANG_Swift
  Julia = dw.DW_LANG_Julia
  Dylan = dw.DW_LANG_Dylan
  C_plus_plus_14 = dw.DW_LANG_C_plus_plus_14
  Fortran03 = dw.DW_LANG_Fortran03
  Fortran08 = dw.DW_LANG_Fortran08
  RenderScript = dw.DW_LANG_RenderScript
  BLISS = dw.DW_LANG_BLISS
  Mips_Assembler = dw.DW_LANG_Mips_Assembler
  Upc = dw.DW_LANG_Upc
  HP_Bliss = dw.DW_LANG_HP_Bliss
  HP_Basic91 = dw.DW_LANG_HP_Basic91
  HP_Pascal91 = dw.DW_LANG_HP_Pascal91
  HP_IMacro = dw.DW_LANG_HP_IMacro
  HP_Assembler = dw.DW_LANG_HP_Assembler
  GOOGLE_RenderScript = dw.DW_LANG_GOOGLE_RenderScript
  BORLAND_Delphi = dw.DW_LANG_BORLAND_Delphi


def partition(items, predicate=bool):
  a, b = tee((predicate(item), item) for item in items)
  return ((item for pred, item in a if pred),
          (item for pred, item in b if not pred))


CONCRETE_SUBPROGRAM_ATTRIBUTES = set([
  'DW_AT_low_pc',
  'DW_AT_high_pc',
  'DW_AT_ranges',
  'DW_AT_entry_pc',
  'DW_AT_location',
  'DW_AT_return_addr',
  'DW_AT_start_scope',
  'DW_AT_segment'
])

TYPE_TAGS = set([
  'DW_TAG_array_type',
  'DW_TAG_base_type',
  'DW_TAG_const_type',
  'DW_TAG_pointer_type',
  'DW_TAG_structure_type',
  'DW_TAG_typedef',
  'DW_TAG_union_type'
])


class SubprogramType(Enum):
  IMPORTED = auto()
  CONCRETE = auto()
  ARTIFICIAL = auto()


def has_name(die: DIE) -> bool:
  return 'DW_AT_name' in die.attributes


def has_size(die: DIE) -> bool:
  return 'DW_AT_byte_size' in die.attributes


def size_of(die: DIE) -> int:
  return die.attributes['DW_AT_byte_size'].value


def has_type(die: DIE) -> bool:
  return 'DW_AT_type' in die.attributes


def has_member_offset(die: DIE) -> bool:
  return 'DW_AT_data_member_location' in die.attributes or 'DW_AT_data_bit_offset' in die.attributes


class UnresolvableDIEError(Exception):
  def __init__(self, source_die, attribute_name):
    self.source_die = source_die
    self.attribute_name = attribute_name

  def __str__(self):
    return f'Unable to resolve the DIE specified by the "{self.attribute_name}" attribute in {self.source_die}'

  def __repr__(self):
    return f'<UnresolvableDIEError: {self.attribute_name}>'


class DWARFData(object):
  def __init__(self, elf_file: ELFFile, debug_root: Optional[str] = None):
    self._elf_file = elf_file
    self._debug_root = debug_root
    self._arch = elf_file.get_machine_arch()
    self._dwarf_info = elf_file.get_dwarf_info()
    self._range_lists = self._dwarf_info.range_lists()
    self._location_lists = self._dwarf_info.location_lists()
    self._die_map = dict()
    self._line_programs = dict()
    self._debug_str = None
    self._logger = logging.getLogger('sidekick.DWARFData')
    self._index()

  def _index(self):
    for cu in self._dwarf_info.iter_CUs():
      self._die_map.update({die.offset: die for die in filter(None, cu.iter_DIEs())})

  def get_alt_filename(self) -> Optional[str]:
    section = self._elf_file.get_section_by_name('.gnu_debugaltlink')
    if section is None:
      section = self._elf_file.get_section_by_name('.gnu_debuglink')
      if section is None:
        section = self._elf_file.get_section_by_name('.debug_sup')
        if section is None:
          return None
    b: bytes = section.data()
    end = b.find(0)
    alt_filename = b[:end].decode('utf-8')
    if alt_filename[0] == '/':
      alt_filename = alt_filename[1:]
    if self._debug_root is None:
      return None
    alt_filename = os.path.join(self._debug_root, alt_filename)
    return alt_filename

  def iter_compile_units(self) -> Iterator[DIE]:
    return filter(lambda die: die.tag == 'DW_TAG_compile_unit', map(lambda cu: cu.get_top_DIE(), self._dwarf_info.iter_CUs()))

  def iter_partial_units(self) -> Iterator[DIE]:
    return filter(lambda die: die.tag == 'DW_TAG_partial_unit', map(lambda cu: cu.get_top_DIE(), self._dwarf_info.iter_CUs()))

  def iter_section_starts(self) -> Iterator[int]:
    return filter(lambda addr: addr > 0, map(lambda section: section['sh_addr'], self._elf_file.iter_sections()))

  def get_die_at_offset(self, offset) -> DIE:
    if offset not in self._die_map:
      raise ValueError(f'offset ({offset}) not in DIE map')
    return self._die_map[offset]

  def get_location_list(self, ll_offset) -> List[Union[LocationEntry, BaseAddressEntry]]:
    assert(self._location_lists)
    return self._location_lists.get_location_list_at_offset(ll_offset)

  def get_line_program(self, die: DIE):
    memo_key = die.cu.cu_die_offset
    if memo_key in self._line_programs:
      return self._line_programs[memo_key]
    line_program = self._dwarf_info.line_program_for_CU(die.cu)
    return self._line_programs.setdefault(memo_key, line_program)

  def get_range_list_at_offset(self, offset):
    assert(self._range_lists)
    return self._range_lists.get_range_list_at_offset(offset)

  def get_debug_str_at_offset(self, offset: int):
    if self._debug_str is None:
      section = self._elf_file.get_section_by_name('.debug_str')
      assert(section is not None)
      self._debug_str = section.data()

    end = self._debug_str.find(0, offset)
    if end == -1:
      end = len(self._debug_str)
    b = self._debug_str[offset:end]
    return b.decode('utf-8')


class DWARFDB(object):
  REFERENCE_FORMS = {
    'DW_FORM_ref1',
    'DW_FORM_ref2',
    'DW_FORM_ref4',
    'DW_FORM_ref8',
    'DW_FORM_ref_addr',
    'DW_FORM_ref_sig8',
    'DW_FORM_ref_sup4',
    'DW_FORM_ref_sup8'
  }

  def __init__(self, elf_file: ELFFile, debug_root: Optional[str] = None):
    self._logger = logging.getLogger('sidekick.DWARFDB')
    self._base_addresses = dict()
    self._pri = DWARFData(elf_file, debug_root)
    self._sup = None
    sup_filename = self._pri.get_alt_filename()
    if sup_filename:
      assert(debug_root)
      self._sup = DWARFData(ELFFile(open(os.path.join(debug_root, sup_filename), 'rb')))
    self._external_decl_files = dict()
    self._index_dwarf_data()

  @property
  def default_address_size(self) -> int:
    return self._pri._dwarf_info.config.default_address_size

  def set_external_decl_file(self, name, filename):
    self._external_decl_files[name] = filename

  def has_external_decl_file(self, name):
    return name in self._external_decl_files

  def get_external_decl_file(self, name):
    return self._external_decl_files[name]

  def _index_dwarf_data(self):
    for top_die in self._pri.iter_partial_units():
      for die in top_die.iter_children():
        if die.tag == 'DW_TAG_subprogram':
          name = self.get_name(die)
          if 'DW_AT_decl_file' in die.attributes:
            self.set_external_decl_file(name, self.get_decl_file(die))

  def process_imported_units(self, unit_die: DIE):
    self._logger.debug(f'Importing unit at {unit_die.cu.cu_offset}')
    for child in unit_die.iter_children():
      if child.tag == 'DW_TAG_imported_unit':
        imported_unit_die = self.get_attr_as_die(child, 'DW_AT_import')
        if imported_unit_die is not None:
          self.process_imported_units(imported_unit_die)

  def iter_compile_units(self) -> Iterator[DIE]:
    return self._pri.iter_compile_units()

  def get_attribute(self, die: DIE, attr_name: str, inheritable: bool = True) -> Optional[Tuple[DIE, AttributeValue]]:
    attr_value = die.attributes.get(attr_name, None)
    if attr_value:
      return (die, attr_value)
    if not inheritable:
      return None
    if 'DW_AT_specification' in die.attributes:
      specification = self.get_attr_as_die(die, 'DW_AT_specification')
      assert(specification)
      result = self.get_attribute(specification, attr_name)
      if result:
        return result
    if 'DW_AT_abstract_origin' in die.attributes:
      abstract_origin = self.get_attr_as_die(die, 'DW_AT_abstract_origin')
      assert(abstract_origin)
      return self.get_attribute(abstract_origin, attr_name)

  def get_attr_as_die(self, die: DIE, attr_name: str) -> Optional[DIE]:
    result = self.get_attribute(die, attr_name)
    if result is None:
      return None
    attr_die, attr_value = result

    if attr_value.form in ['DW_FORM_ref1', 'DW_FORM_ref2', 'DW_FORM_ref4', 'DW_FORM_ref8', 'DW_FORM_ref_udata']:
      if attr_die.cu.dwarfinfo == self._pri._dwarf_info:
        return self._pri.get_die_at_offset(attr_value.value + attr_die.cu.cu_offset)
      elif self._sup is not None:
        return self._sup.get_die_at_offset(attr_value.value + attr_die.cu.cu_offset)
    elif attr_value.form == 'DW_FORM_ref_addr':
      if attr_die.cu.dwarfinfo == self._pri._dwarf_info:
        return self._pri.get_die_at_offset(attr_value.value)
      elif self._sup is not None:
        return self._sup.get_die_at_offset(attr_value.value)
    elif attr_value.form == 'DW_FORM_GNU_ref_alt':
      if self._sup is not None:
        return self._sup.get_die_at_offset(attr_value.value)

    self._logger.warning(f'unsupported form ("{attr_value.form}") while getting attribute ("{attr_name}") as DIE')
    return None

  def get_attr_as_constant(self, die: DIE, attr_name: str) -> Optional[Any]:
    die_attr_pair = self.get_attribute(die, attr_name)
    if die_attr_pair is None:
      return None
    attr_die, attr_value = die_attr_pair
    return attr_value.value

  def get_attr_as_string(self, die: DIE, attr_name: str) -> Optional[str]:
    die_attr_pair = self.get_attribute(die, attr_name)
    if die_attr_pair is None:
      return None
    attr_die, attr_value = die_attr_pair

    if type(attr_value.value) == bytes:
      return attr_value.value.decode('utf-8')
    elif attr_value.form == 'DW_FORM_strp':
      return self._pri.get_debug_str_at_offset(attr_value.value)
    elif attr_value.form in ['DW_FORM_GNU_strp_alt', 'DW_FORM_strp_sup']:
      if self._sup is None:
        raise Exception('Reference to missing supplemental debug file')
      return self._sup.get_debug_str_at_offset(attr_value.value)
    return None

  def get_attr_as_int(self, die: DIE, attr_name: str) -> Optional[int]:
    die_attr_pair = self.get_attribute(die, attr_name)
    if die_attr_pair is None:
      return None
    attr_die, attr_value = die_attr_pair
    assert(isinstance(attr_value.value, int))
    return attr_value.value

  def get_type_attr_as_die(self, die: DIE) -> Optional[DIE]:
    return self.get_attr_as_die(die, 'DW_AT_type')

  def get_qualified_name(self, die: DIE) -> QualifiedName:
    if (
      die._parent is not None
      and die._parent.tag in {
        'DW_TAG_structure_type',
        'DW_TAG_class_type',
        'DW_TAG_interface_type',
        'DW_TAG_union_type',
        'DW_TAG_namespace'}
    ):
      qname = self.get_qualified_name(die._parent)
      uname = self.get_name(die)
      if uname is None:
        uname = 'anonymous'
      return QualifiedName(*qname, uname)
    else:
      if die.tag in ['DW_TAG_subprogram', 'DW_TAG_inlined_subroutine']:
        if 'DW_AT_abstract_origin' in die.attributes:
          origin_die = self.get_attr_as_die(die, 'DW_AT_abstract_origin')
          assert(origin_die)
          return self.get_qualified_name(origin_die)
        if 'DW_AT_specification' in die.attributes:
          specification = self.get_attr_as_die(die, 'DW_AT_specification')
          assert(specification)
          return self.get_qualified_name(specification)
      n = self.get_name(die)
      if n is None:
        return QualifiedName()
      else:
        return QualifiedName(n)

  def get_name(self, die: DIE) -> Optional[str]:
    return self.get_attr_as_string(die, 'DW_AT_name')

  def get_start_address(self, die: DIE) -> Optional[int]:
    if 'DW_AT_entry_pc' in die.attributes:
      return die.attributes['DW_AT_entry_pc'].value
    if 'DW_AT_ranges' in die.attributes:
      if die.cu.dwarfinfo == self._pri._dwarf_info:
        ranges = self._pri.get_range_list_at_offset(die.attributes['DW_AT_ranges'].value)
      elif self._sup is not None:
        ranges = self._sup.get_range_list_at_offset(die.attributes['DW_AT_ranges'].value)
      else:
        ranges = []
      for r in ranges:
        if type(r) == elftools.dwarf.ranges.BaseAddressEntry:
          return r.base_address
        else:
          return r.begin_offset
    if 'DW_AT_low_pc' in die.attributes:
      low_pc = die.attributes['DW_AT_low_pc']
      if low_pc.form == 'DW_FORM_addr':
        addr = die.attributes['DW_AT_low_pc'].value
        return addr if addr != 0 else None
      else:
        raise NotImplementedError('Unsupported DW_FORM for AT_low_pc')
    return None

  def get_ranges(self, die: DIE) -> Optional[List[Tuple[int, int]]]:
    ranges = []
    if 'DW_AT_low_pc' in die.attributes:
      if 'DW_AT_high_pc' in die.attributes:
        high_pc = die.attributes['DW_AT_high_pc']
        if high_pc.form == 'DW_FORM_addr':
          ranges.append((die.attributes['DW_AT_low_pc'].value, die.attributes['DW_AT_high_pc'].value))
        else:
          base = die.attributes['DW_AT_low_pc'].value
          offset = die.attributes['DW_AT_high_pc'].value
          ranges.append((base, base + offset))
      else:
        ranges.append((die.attributes['DW_AT_low_pc'].value, die.attributes['DW_AT_low_pc'].value))
    elif 'DW_AT_ranges' in die.attributes:
      if die.cu.dwarfinfo == self._pri._dwarf_info:
        range_list = self._pri.get_range_list_at_offset(die.attributes['DW_AT_ranges'].value)
      elif self._sup is not None:
        range_list = self._sup.get_range_list_at_offset(die.attributes['DW_AT_ranges'].value)
      else:
        range_list = []
      base_addr = self.get_cu_base_address(die.cu)
      if base_addr is None:
        raise Exception('Unable to obtain the compilation unit base address')
      for entry in range_list:
        if isinstance(entry, elftools.dwarf.ranges.RangeEntry):
          ranges.append((base_addr + entry.begin_offset, base_addr + entry.end_offset))
        elif isinstance(entry, elftools.dwarf.ranges.BaseAddressEntry):
          base_addr = entry.base_address
        else:
          assert(False)
    return ranges if ranges else None

  def min_mapped_address(self) -> int:
    min_addr = sys.maxsize
    for start in self._pri.iter_section_starts():
      if start < min_addr:
        min_addr = start
    if self._sup:
      for start in self._sup.iter_section_starts():
        if start < min_addr:
          min_addr = start
    return min_addr

  def is_concrete_subprogram(self, die):
    return any(map(lambda attr_name: attr_name in CONCRETE_SUBPROGRAM_ATTRIBUTES, die.attributes.keys()))

  def is_subprogram_declared_external(self, die):
    return (
      'DW_AT_external' in die.attributes
      and 'DW_AT_declaration' in die.attributes
      and 'DW_AT_decl_file' in die.attributes
    )

  def is_concrete_variable(self, die):
    return any(map(lambda attr_name: attr_name in CONCRETE_SUBPROGRAM_ATTRIBUTES, die.attributes.keys()))

  def get_decl_file(self, die: DIE) -> Optional[str]:
    file_id = self.get_attr_as_int(die, 'DW_AT_decl_file')
    if file_id is not None:
      file_index = file_id - 1
      if file_index >= 0:
        line_program = self._pri.get_line_program(die)
        filename = line_program['file_entry'][file_index]['name'].decode('utf-8')
        return os.path.normpath(filename)
    return None

  def get_attr_as_location_list(self, die: DIE, attr_name: str) -> Optional[List[LocationEntry]]:
    result = self.get_attribute(die, attr_name)
    if result is None:
      return None

    loc_die, loc_attr = result
    if loc_attr.form in ['DW_FORM_exprloc', 'DW_FORM_block1']:
      return [LocationEntry(entry_offset=0, begin_offset=0, end_offset=0, loc_expr=loc_attr.value)]
    elif loc_attr.form == 'DW_FORM_sec_offset':
      locations: List[LocationEntry] = []
      assert(loc_die.cu.dwarfinfo == self._pri._dwarf_info)
      base = None
      for entry in self._pri.get_location_list(loc_attr.value):
        if isinstance(entry, LocationEntry):
          if base is None:
            cu_base = self.get_cu_base_address(loc_die.cu)
            if cu_base is not None:
              cu_end = cu_base + loc_die.cu.size
              if (cu_base <= entry.begin_offset and entry.begin_offset < cu_end):
                base = 0
              else:
                base = cu_base
            else:
              base = 0
          locations.append(
            LocationEntry(
              entry_offset=entry.entry_offset,
              begin_offset=base + entry.begin_offset,
              end_offset=base + entry.end_offset,
              loc_expr=entry.loc_expr))
        elif isinstance(entry, BaseAddressEntry):
          b: int = entry.base_address
          base = b
        else:
          assert(False)
      return locations

    elif loc_attr.form == 'DW_FORM_data4':
      base = self.get_cu_base_address(loc_die.cu)
      locations: List[LocationEntry] = []
      assert(loc_die.cu.dwarfinfo == self._pri._dwarf_info)
      for entry in self._pri.get_location_list(loc_attr.value):
        if isinstance(entry, LocationEntry):
          if base is None:
            locations.append(
              LocationEntry(
                entry_offset=entry.entry_offset,
                begin_offset=entry.begin_offset,
                end_offset=entry.end_offset,
                loc_expr=entry.loc_expr))
          else:
            locations.append(
              LocationEntry(
                entry_offset=entry.entry_offset,
                begin_offset=base + entry.begin_offset,
                end_offset=base + entry.end_offset,
                loc_expr=entry.loc_expr))
        elif isinstance(entry, BaseAddressEntry):
          base = entry.base_address
        else:
          assert(False)
      return locations

    else:
      self._logger.error(f'unhandled location form {loc_attr.form}')
    assert(False)

  def get_location_list(self, die: DIE) -> List[LocationEntry]:
    result = self.get_attr_as_location_list(die, 'DW_AT_location')
    return result if result is not None else []

  def get_cu_base_address(self, cu: CompileUnit) -> Optional[int]:
    base = self._base_addresses.get(cu, None)
    if base is None:
      top_die = cu.get_top_DIE()
      assert top_die.tag == 'DW_TAG_compile_unit'
      base = self._base_addresses.setdefault(cu, self.get_start_address(top_die))
    return base

  def get_array_count(self, die: DIE) -> Optional[int]:
    for d in die.iter_children():
      if d.tag == 'DW_TAG_subrange_type':
        if 'DW_AT_count' in d.attributes:
          return d.attributes['DW_AT_count'].value
        if 'DW_AT_upper_bound' in d.attributes:
          upper_bound = d.attributes['DW_AT_upper_bound']
          if upper_bound.form == 'DW_FORM_exprloc':
            return None
          if upper_bound.form in DWARFDB.REFERENCE_FORMS:
            return None
          ub = upper_bound.value
          if 'DW_AT_lower_bound' in d.attributes:
            lb = d.attributes['DW_AT_lower_bound'].value
            return ub - lb
          assert(isinstance(ub, int))
          return ub + 1
    return None


def qualified_name_to_str(qname: Union[Tuple[str], str]):
  return '::'.join(qname) if isinstance(qname, tuple) else qname


def split_all_path_parts(path: str):
  import os.path
  allparts = []
  path = os.path.normpath(path)
  while 1:
    parts = os.path.split(path)
    if parts[0] == path:
      allparts.insert(0, parts[0])
      break
    elif parts[1] == path:
      allparts.insert(0, parts[1])
      break
    else:
      path = parts[0]
      allparts.insert(0, parts[1])
  return allparts


class DWARFImporter(object):
  def __init__(self, dwarf_db: DWARFDB, query, model: AnalysisModel, logger: Optional[logging.Logger] = None):
    self._dwarf_db = dwarf_db
    self._model = model
    self._query = query
    self._type_factory = TypeFactory(dwarf_db)
    self._location_factory = LocationFactory(dwarf_db)
    self._min_section_addr = self._dwarf_db.min_mapped_address()
    self._globals_filter = query.get('globals_filter', lambda qname: True)
    self._include_imports = query.get('include_imports', True)
    self._include_variables = query.get('include_variables', True)
    self._include_subprograms = query.get('include_subprograms', True)
    self._only_concrete_subprograms = query.get('only_concrete_subprograms', True)
    self._include_parameters = query.get('include_parameters', True)
    self._include_local_variables = query.get('include_local_variables', True)
    self._include_inlined_functions = query.get('include_inlined_functions', True)
    self._include_global_variable_references = query.get('include_global_variable_references', True)
    self._include_subprogram_decls = query.get('include_subprogram_decls', True)
    self._compile_unit_filter = query.get('cu_filter', None)
    self._die_map = dict()
    self._imported_subprograms: MutableMapping[str, Set[str]] = defaultdict(set)
    self._imported_start_addrs: Set[int] = set()
    if logger is not None:
      self._logger = logger.getChild('DWARFImporter')
    else:
      self._logger = logging.getLogger('sidekick.DWARFImporter')
    self._component: Optional[Component] = None

  def import_debug_info(self):
    for cu_die in self._dwarf_db.iter_compile_units():
      name = self._dwarf_db.get_name(cu_die)
      if self._compile_unit_filter and name not in self._compile_unit_filter:
        continue
      if name is None:
        name = 'anonymous'
      qname = QualifiedName(*split_all_path_parts(name))
      language = self._dwarf_db.get_attr_as_int(cu_die, 'DW_AT_language')
      if language is not None:
        language = Language(language).name
      producer = self._dwarf_db.get_attr_as_string(cu_die, 'DW_AT_producer')

      self._component = self._model.make_leaf_component(qname)
      if language is not None:
        self._component.attributes['language'] = language
      if producer is not None:
        self._component.attributes['producer'] = producer

      self._type_factory._component = self._component
      self.import_compilation_unit(cu_die)
      self._component = None

    for ty in self._type_factory._definitions.values():
      self._model.add_type(ty)

  def import_compilation_unit(self, die: DIE):
    if die.tag == 'DW_TAG_compile_unit':
      cu_name = self._dwarf_db.get_name(die)
      self._logger.debug('--' + (cu_name.ljust(78, '-') if cu_name else ''))
      self._base_address = self._dwarf_db.get_start_address(die)
    for child in die.iter_children():
      if child.tag == 'DW_TAG_subprogram':
        if self._include_subprograms:
          self.import_subprogram(child)
      elif child.tag == 'DW_TAG_variable':
        if self._include_variables:
          if self.is_global_variable(child):
            self.import_global_variable(child)
          elif self.is_global_constant(child):
            self.import_global_constant(child)
      elif child.tag == 'DW_TAG_imported_declaration':
        if self._include_imports:
          self.import_imported_declaration(child)
      elif child.tag in [
        'DW_TAG_namespace',
        'DW_TAG_class_type',
        'DW_TAG_interface_type',
        'DW_TAG_structure_type',
        'DW_TAG_union_type'
      ]:
        self.import_compilation_unit(child)
      elif child.tag == 'DW_TAG_module' and 'DW_AT_declaration' in child.attributes:
        pass
      elif child.tag in [
        'DW_TAG_imported_unit',
        'DW_TAG_typedef',
        'DW_TAG_unspecified_type',
        'DW_TAG_base_type',
        'DW_TAG_const_type',
        'DW_TAG_volatile_type',
        'DW_TAG_restrict_type',
        'DW_TAG_array_type',
        'DW_TAG_enumeration_type',
        'DW_TAG_pointer_type',
        'DW_TAG_reference_type',
        'DW_TAG_ptr_to_member_type',
        'DW_TAG_subroutine_type',
        'DW_TAG_rvalue_reference_type',
        'DW_TAG_subrange_type',
        'DW_TAG_string_type',
        'DW_TAG_member',
        'DW_TAG_inheritance',
        'DW_TAG_template_type_param',
        'DW_TAG_template_value_param',
        'DW_TAG_GNU_template_template_param',
        'DW_TAG_GNU_template_parameter_pack',
        'DW_TAG_imported_module',
        'DW_TAG_module',
        'DW_TAG_imported_declaration',
        'DW_TAG_dwarf_procedure',
        'DW_TAG_constant'
      ]:
        pass
      else:
        print(child.tag, '(child tag)')

  def is_global_variable(self, die: DIE) -> bool:
    attr = self._dwarf_db.get_attribute(die, 'DW_AT_declaration', False)
    if attr is not None:
      return False
    locations = self._dwarf_db.get_location_list(die)
    return len(locations) != 0

  def is_global_constant(self, die: DIE) -> bool:
    if 'DW_AT_declaration' in die.attributes:
      return False
    locations = self._dwarf_db.get_location_list(die)
    if len(locations) > 0:
      return False
    constant_value = self._dwarf_db.get_attr_as_constant(die, 'DW_AT_const_value')
    return constant_value is not None

  def import_global_variable(self, die: DIE):
    locations = self._dwarf_db.get_location_list(die)
    if len(locations) == 0:
      return
    qname = self._dwarf_db.get_qualified_name(die)
    if not self._globals_filter(qname):
      return
    name = qualified_name_to_str(qname)
    assert(name is not None)
    self._logger.debug(f'Importing global variable {name}')
    type_die = self._dwarf_db.get_type_attr_as_die(die)
    assert(type_die)
    var_type = self._type_factory.make_user_type(type_die)

    address = None
    for _, begin, end, loc_expr in locations:
      loc = self._location_factory.make_location(begin, end, loc_expr)
      if loc and loc.type == LocationType.STATIC_GLOBAL:
        address = loc.expr[0]
        assert(isinstance(address, int))
        break
    if address is None:
      v = Variable(name=qname, addr=None, type=var_type)
    elif address >= self._min_section_addr:
      v = Variable(name=qname, addr=address, type=var_type)
    else:
      self._logger.debug(f'Variable address is greater than the minimum section address ({self._min_section_addr:x})')
      return

    self._model.add_variable(v)

  def import_global_constant(self, die: DIE):
    constant_value = self._dwarf_db.get_attr_as_constant(die, 'DW_AT_const_value')
    if constant_value is not None:
      qname = self._dwarf_db.get_qualified_name(die)
      type_die = self._dwarf_db.get_type_attr_as_die(die)
      assert(type_die)
      value_type = self._type_factory.make_user_type(type_die)
      c = Constant(name=qname, type=value_type, value=constant_value)
      self._model.add_constant(c)

  def import_imported_declaration(self, die: DIE):
    import_die = self._dwarf_db.get_attr_as_die(die, 'DW_AT_import')
    if import_die is None:
      return
    qname = self._dwarf_db.get_qualified_name(import_die)
    name = qualified_name_to_str(qname)
    decl_file = self._dwarf_db.get_decl_file(die)
    if decl_file:
      self._imported_subprograms[decl_file].add(name)

  def import_location_list(self, location_list):
    if location_list is None:
      return None
    locations = []
    for loc in location_list:
      r = self._location_factory.make_location(loc.begin_offset, loc.end_offset, loc.loc_expr)
      if r is not None:
        locations.append(r)
    if len(locations) == 1:
      return locations[0]
    elif len(locations) == 0:
      return None
    else:
      return locations

  def import_subprogram(self, die: DIE):
    is_concrete = self._dwarf_db.is_concrete_subprogram(die)
    if not is_concrete:
      if self._include_subprogram_decls and self._dwarf_db.is_subprogram_declared_external(die):
        qname = self._dwarf_db.get_qualified_name(die)
        name = qualified_name_to_str(qname)
        self._dwarf_db.set_external_decl_file(name, self._dwarf_db.get_decl_file(die))
      if self._only_concrete_subprograms:
        return
    qname = self._dwarf_db.get_qualified_name(die)
    if not self._globals_filter(qname):
      return
    start_addr = self._dwarf_db.get_start_address(die)
    if start_addr is not None and self._model.get_function_at(start_addr):
      return
    function = Function(name=qname, entry_addr=start_addr)
    return_type_die = self._dwarf_db.get_type_attr_as_die(die)
    if return_type_die is None:
      return_type = VOID
    else:
      return_type = self._type_factory.make_user_type(return_type_die)
    function.set_return_type(return_type)
    function.no_return = True if self._dwarf_db.get_attribute(die, 'DW_AT_noreturn') else False
    function.frame_base = self.import_location_list(self._dwarf_db.get_attr_as_location_list(die, 'DW_AT_frame_base'))
    function.ranges = self._dwarf_db.get_ranges(die)
    if self._include_subprogram_decls:
      if self._dwarf_db.has_external_decl_file(str(qname)):
        decl_file = self._dwarf_db.get_external_decl_file(str(qname))
        if decl_file is not None:
          function.set_attribute('decl_file', decl_file)
    function.arch = self.get_function_arch(function)
    location_map = defaultdict(list)
    abstract_map = dict()
    self.import_local_elements(die, function, None, location_map=location_map, abstract_map=abstract_map)
    self.apply_variable_hiding(location_map)
    global_vars = self.extract_global_variables(function)
    self._model.add_function(function)
    assert(self._component is not None)
    self._component.add_elements(function)
    self._component.add_elements(global_vars)

  def get_function_arch(self, function: Function):
    arch = self._dwarf_db._pri._arch
    if arch == 'ARM':
      for section in self._dwarf_db._pri._elf_file.iter_sections():
        if not isinstance(section, SymbolTableSection):
          continue
        for symbol in section.iter_symbols():
          if symbol.entry['st_info']['type'] != 'STT_FUNC':
            continue
          addr = symbol.entry['st_value']
          if ((addr & ~0x1) != function.entry_addr):
            continue
          return 'Thumb' if (addr & 0x1) else 'ARM'
    return arch

  def extract_global_variables(self, function: Function):
    global_vars = []
    for v in function.iter_variables():
      global_locations = list(loc for loc in v.locations if loc.type == LocationType.STATIC_GLOBAL)
      if global_locations:
        for g in global_locations:
          if isinstance(g.expr[0], int):
            global_vars.append(Variable(name=v.name, addr=g.expr[0], type=v.type))
            v.locations.remove(g)
    return global_vars

  def apply_variable_hiding(self, location_map):
    for loc, elements in location_map.items():
      if len(elements) > 1:
        j = None
        for i in range(len(elements) - 1, 0, -1):
          if elements[i].type != elements[i - 1].type:
            j = i
            break
        if j is None:
          continue
        while j < len(elements) - 1 and elements[j].name in ['this', '__artificial__']:
          j += 1
        for i in range(0, j):
          elements[i].locations.remove(loc)

  def import_inlined_subroutine(self, die: DIE, parent_function: Function, location_map, abstract_map):
    qname = self._dwarf_db.get_qualified_name(die)
    name = qualified_name_to_str(qname)
    self._logger.debug(f'inlined subroutine {name}')
    start = self._dwarf_db.get_start_address(die)
    function = Function(name=qname, entry_addr=start)
    function.is_inlined = True
    type_die = self._dwarf_db.get_type_attr_as_die(die)
    function.ranges = self._dwarf_db.get_ranges(die)
    if type_die is not None:
      function.set_return_type(self._type_factory.make_user_type(type_die))
    function.frame_base = self.import_location_list(self._dwarf_db.get_attr_as_location_list(die, 'DW_AT_frame_base'))
    self.import_local_elements(die, function, parent_function, location_map=location_map, abstract_map=abstract_map)
    return function

  def import_local_elements(
    self,
    die: DIE, function: Function,
    parent_function: Optional[Function],
    inside_lexical_block: bool = False,
    location_map=None, abstract_map=None
  ):
    for child in die.iter_children():
      if child.tag == 'DW_TAG_variable':
        if self._include_local_variables:
          if self._dwarf_db.is_concrete_variable(child):
            local_var = self.import_local_variable(child, function, abstract_map)
            if local_var:
              self.import_locations(
                local_var, child, location_map,
                [LocationType.STATIC_LOCAL, LocationType.STATIC_GLOBAL])
      elif child.tag == 'DW_TAG_formal_parameter':
        if self._include_parameters:
          param = self.import_parameter(child, function, parent_function, abstract_map)
          if param:
            self.import_locations(param, child, location_map, [LocationType.STATIC_LOCAL])
      elif child.tag == 'DW_TAG_unspecified_parameters':
        function.append_parameter(None, VARIADIC)
      elif child.tag == 'DW_TAG_lexical_block':
        self.import_local_elements(
          child, function, parent_function,
          inside_lexical_block=True, location_map=location_map, abstract_map=abstract_map)
      elif child.tag == 'DW_TAG_inlined_subroutine':
        if self._include_inlined_functions:
          f = self.import_inlined_subroutine(
            child, function if parent_function is None else parent_function,
            location_map, abstract_map)
          function.add_inlined_function(f)
      elif child.tag == 'DW_TAG_subprogram':
        if self._dwarf_db.is_concrete_subprogram(child):
          self.import_subprogram(child)
        else:
          pass
      elif child.tag in [
        'DW_TAG_template_type_parameter',
        'DW_TAG_template_type_param',
        'DW_TAG_template_value_param',
        'DW_TAG_GNU_formal_parameter_pack',
        'DW_TAG_GNU_template_parameter_pack',
        'DW_TAG_GNU_template_template_param',
        'DW_TAG_GNU_call_site',
        'DW_TAG_label',
        'DW_TAG_imported_declaration',
        'DW_TAG_constant',
        'DW_TAG_imported_module',
        'DW_TAG_common_block',
        'DW_TAG_namelist',
        'DW_TAG_subrange_type',
        'DW_TAG_typedef',
        'DW_TAG_array_type',
        'DW_TAG_structure_type',
        'DW_TAG_union_type',
        'DW_TAG_class_type',
        'DW_TAG_interface_type',
        'DW_TAG_const_type',
        'DW_TAG_pointer_type',
        'DW_TAG_enumeration_type',
        'DW_TAG_reference_type',
        'DW_TAG_restrict_type'
      ]:
        pass
      else:
        self._logger.warning(f'unhandled tag {child.tag} inside {die.tag}\n\tParent DIE = {die}\n\tChild DIE  = {child}')

  def import_parameter(self, die: DIE, function: Function, parent_function: Optional[Function], abstract_map):
    if 'DW_AT_abstract_origin' in die.attributes:
      abstract_origin = self._dwarf_db.get_attr_as_die(die, 'DW_AT_abstract_origin')
      if abstract_origin in abstract_map:
        return abstract_map[abstract_origin]
    else:
      abstract_origin = None

    name = self._get_parameter_name(die)
    if name is None:
      name = ''
      self._logger.debug(f'in {function.name}: unnamed parameter\n{die})')
    if name is not None:
      type_die = self._dwarf_db.get_type_attr_as_die(die)
      if type_die is not None:
        parameter_type = self._type_factory.make_user_type(type_die)
        p = function.append_parameter(name, parameter_type)

        if 'DW_AT_abstract_origin' in die.attributes:
          abstract_map[abstract_origin] = p

        return p
      else:
        self._logger.warning(f'In "{function.name}", parameter "{name}" has no type {die}')
    else:
      self._logger.warning(f'parameter has no name {die}')
      self._logger.warning(f'parameter type {self._type_factory.type_of(die)}')
      name = 'anonymous'

  def import_locations(
    self,
    element: Union[Parameter, LocalVariable],
    die: DIE,
    location_map: MutableMapping[Location, List[Element]],
    location_filter
  ):
    for _, begin, end, loc_expr in self._dwarf_db.get_location_list(die):
      loc = self._location_factory.make_location(begin, end, loc_expr)
      if loc and loc.type in location_filter:
        element.add_location(loc)
        location_map[loc].append(element)

  def import_local_variable(self, die: DIE, fn: Function, abstract_map):
    if 'DW_AT_abstract_origin' in die.attributes:
      abstract_origin = self._dwarf_db.get_attr_as_die(die, 'DW_AT_abstract_origin')
      if abstract_origin in abstract_map:
        return abstract_map[abstract_origin]
    else:
      abstract_origin = None

    name = self._get_local_variable_name(die)
    if name is None:
      return None

    try:
      type_die = self._dwarf_db.get_type_attr_as_die(die)
      if type_die is None:
        self._logger.error(f'Local variable ({name}) has no type {die}')
        raise Exception(f'Local variable ({name}) has no type {die}')
      assert(type_die is not None)
      var_type = self._type_factory.make_user_type(type_die)

      if 'DW_AT_const_value' in die.attributes and 'DW_AT_location' not in die.attributes:
        fn.add_constant(name, var_type, die.attributes['DW_AT_const_value'].value)
      else:
        v = fn.add_variable(name, var_type)
        if 'DW_AT_abstract_origin' in die.attributes:
          abstract_map[abstract_origin] = v
        return v
    except Exception as e:
      self._logger.exception("importing local variable", exc_info=sys.exc_info())
      raise e

  def _get_parameter_name(self, die):
    if 'DW_AT_artificial' in die.attributes:
      return 'this'
    else:
      return self._dwarf_db.get_name(die)

  def _get_local_variable_name(self, die) -> Optional[str]:
    if 'DW_AT_artificial' in die.attributes:
      return '__artificial__'
    else:
      return self._dwarf_db.get_name(die)


class TypeFactory(object):
  def __init__(self, dwarf_db: DWARFDB):
    self._dwarf_db = dwarf_db
    self._addr_size = dwarf_db._pri._dwarf_info.config.default_address_size
    self._defined_types: MutableMapping[DIE, Type] = dict()
    self._base_types: MutableMapping[str, Type] = dict()
    self._named_composites: MutableMapping[str, Type] = dict()
    self._logger = logging.getLogger('sidekick.TypeFactory')
    self._definitions = dict()
    self._component: Optional[Component] = None
    structs = self._dwarf_db._pri._dwarf_info.structs
    arch = self._dwarf_db._pri._arch
    self._expr_parser = LocExprParser(structs, arch)

  def clear(self):
    self._defined_types = dict()

  def iter_types(self) -> ValuesView[Type]:
    return self._defined_types.values()

  def name_of(self, die: DIE) -> Optional[str]:
    return self._dwarf_db.get_name(die)

  def type_of(self, die: DIE) -> DIE:
    type_die = self._dwarf_db.get_type_attr_as_die(die)
    assert(type_die)
    return type_die

  def make_user_type(self, type_die: DIE, alias: Optional[QualifiedName] = None) -> Type:
    visited = []
    return self._make_user_type_helper(type_die, alias, visited)

  def _make_user_type_helper(self, type_die: DIE, alias: Optional[QualifiedName] = None, visited=None) -> Type:
    if type_die in self._defined_types:
      return self._defined_types[type_die]

    assert(type_die)

    if type_die in visited:
      if type_die.tag == 'DW_TAG_pointer_type':
        return VOID_PTR
      else:
        return VOID

    if type_die.tag == 'DW_TAG_base_type':
      n = self.name_of(type_die)
      if n is None:
        raise Exception('Base type must have a name')
      base_type = BaseType(n, byte_size=size_of(type_die))
      self._base_types[str(base_type.name)] = base_type
      return self._defined_types.setdefault(type_die, base_type)

    elif type_die.tag == 'DW_TAG_unspecified_type':
      n = self.name_of(type_die)
      if n is None:
        raise Exception('Unspecified type must have a name')
      unspecified_type = BaseType(n, None)
      return self._defined_types.setdefault(type_die, unspecified_type)

    elif type_die.tag == 'DW_TAG_typedef':
      qualified_alias = self._dwarf_db.get_qualified_name(type_die)
      aliased_type_die = self._dwarf_db.get_type_attr_as_die(type_die)
      if aliased_type_die:
        visited.append(type_die)
        element_type = self._make_user_type_helper(aliased_type_die, alias=qualified_alias, visited=visited)
        visited.pop()
      else:
        element_type = VOID
      if element_type.name == qualified_alias:
        return element_type
      else:
        alias_type = AliasType(name=qualified_alias, type=element_type)
        if alias_type.name in self._definitions:
          return self._definitions[alias_type.name]
        else:
          self._definitions[alias_type.name] = alias_type
        return self._defined_types.setdefault(type_die, alias_type)

    elif type_die.tag in ['DW_TAG_const_type', 'DW_TAG_volatile_type']:
      if has_type(type_die):
        try:
          visited.append(type_die)
          element_type = self._make_user_type_helper(self.type_of(type_die), visited=visited)
          visited.pop()
        except Exception as e:
          self._logger.error(str(e))
          raise e
      else:
        element_type = VOID
      if type_die.tag == 'DW_TAG_const_type':
        cv_type = ConstType(type=element_type)
      else:
        cv_type = VolatileType(type=element_type)
      return self._defined_types.setdefault(type_die, cv_type)

    elif type_die.tag in ['DW_TAG_pointer_type', 'DW_TAG_reference_type', 'DW_TAG_rvalue_reference_type']:
      if has_type(type_die):
        visited.append(type_die)
        element_type = self._make_user_type_helper(self.type_of(type_die), visited=visited)
        visited.pop()
      else:
        element_type = VOID
      pointer_size = size_of(type_die) if has_size(type_die) else self._addr_size
      pointer_type = PointerType(target_type=element_type, byte_size=pointer_size)
      if type_die.tag == 'DW_TAG_reference_type':
        pointer_type.nullable = False
      elif type_die.tag == 'DW_TAG_rvalue_reference_type':
        pointer_type.nullable = False
      if has_name(type_die):
        n = self.name_of(type_die)
        assert(n)
        alias_type = AliasType(name=QualifiedName(n), type=pointer_type)
        return self._defined_types.setdefault(type_die, alias_type)
      else:
        return self._defined_types.setdefault(type_die, pointer_type)

    elif type_die.tag in ['DW_TAG_structure_type', 'DW_TAG_class_type', 'DW_TAG_union_type', 'DW_TAG_interface_type']:
      composite_name = self.get_type_name(type_die, alias)
      composite_size = size_of(type_die) if has_size(type_die) else None
      if type_die.tag == 'DW_TAG_structure_type':
        composite_type = StructType(name=composite_name, byte_size=composite_size)
      elif type_die.tag == 'DW_TAG_union_type':
        composite_type = UnionType(name=composite_name, byte_size=composite_size)
      elif type_die.tag == 'DW_TAG_class_type':
        composite_type = ClassType(name=composite_name, byte_size=composite_size)
      elif type_die.tag == 'DW_TAG_interface_type':
        composite_type = ClassType(name=composite_name, byte_size=composite_size)
      else:
        assert(False)
      self._defined_types[type_die] = composite_type
      for member_die in type_die.iter_children():
        if member_die.tag == 'DW_TAG_member':
          if not has_type(member_die):
            raise Exception('Member has no type')

          visited.append(type_die)
          member_type = self._make_user_type_helper(self.type_of(member_die), visited=visited)
          visited.pop()

          if member_type.name is None:
            assert(member_type.name is not None)
          member_offset = self.member_offset_of(member_die)
          if member_offset is None and isinstance(composite_type, UnionType) and 'DW_AT_declaration' not in member_die.attributes:
            member_offset = 0
          if member_offset is not None:
            n = self.name_of(member_die)
            if n is not None:
              composite_type.add_field(Field(name=n, offset=member_offset, type=member_type))
            else:
              composite_type.add_unnamed_field(Field(name=None, offset=member_offset, type=member_type))
          else:
            if 'DW_AT_const_value' in member_die.attributes:
              pass
            elif 'DW_AT_declaration' in member_die.attributes:
              pass
            else:
              raise NotImplementedError('member with no offset')
        elif member_die.tag == 'DW_TAG_inheritance':
          member_type_die = self.type_of(member_die)
          visited.append(type_die)
          member_type = self._make_user_type_helper(member_type_die, visited=visited)
          visited.pop()
          member_offset = self.member_offset_of(member_die)
          if member_offset is not None:
            if member_type.byte_size is None:
              self._logger.debug(f'Member type size is None {member_type}')
            composite_type.add_unnamed_field(Field(name=None, offset=member_offset, type=member_type))
          else:
            self._logger.warning(f'Unsupported: inherited composite ({member_type.name}) at a computed offset')
        elif member_die.tag == 'DW_TAG_variant_part':
          pass
      self._defined_types[type_die] = composite_type
      if composite_type.name.is_anonymous is False:
        if composite_type.name in self._definitions:
          existing_ty = self._definitions[composite_type.name]
          if isinstance(existing_ty, CompositeType):
            if len(existing_ty) >= 0 and len(composite_type) == 0:
              return existing_ty
            elif len(composite_type) > 0 and len(existing_ty) == 0:
              existing_ty.merge_from(composite_type)
              return existing_ty
            elif existing_ty.byte_size is None and composite_type.byte_size is not None:
              existing_ty.merge_from(composite_type)
              return existing_ty
            elif existing_ty.is_equivalent(composite_type):
              return existing_ty

          assert(self._component is not None)
          composite_type.name = QualifiedName(self._component.name, *composite_type.name)
          self._logger.debug(f'Conflicting type name.  Adding qualifier. ({composite_type.name})')
          self._logger.debug(f'Existing type: ({existing_ty.__repr__()})')
          if isinstance(existing_ty, CompositeType):
            self._logger.debug(f'{existing_ty.byte_size=}, {existing_ty.policy.name=}, {existing_ty.name=}')
          self._logger.debug(f'Current type: ({composite_type.__repr__()})')
          self._logger.debug(f'{composite_type.byte_size=}, {composite_type.policy.name=}, {composite_type.name=}')
          self._definitions[composite_type.name] = composite_type
          return self._definitions[composite_type.name]
        else:
          self._definitions[composite_type.name] = composite_type
      return composite_type

    elif type_die.tag in ['DW_TAG_enumeration_type']:
      enum_name = self.get_type_name(type_die, alias)
      enum_size = size_of(type_die) if has_size(type_die) else self._addr_size
      enum_type = EnumType(name=enum_name, byte_size=enum_size)
      for member_die in type_die.iter_children():
        if member_die.tag == 'DW_TAG_enumerator':
          value = member_die.attributes['DW_AT_const_value'].value
          label = self.name_of(member_die)
          if label is None:
            raise Exception('DW_TAG_enumeration_type has no label')
          enum_type.add_enumerator(Enumerator(label=label, value=value))
      if enum_type.name:
        if enum_type.name in self._definitions:
          return self._definitions[enum_type.name]
        else:
          self._definitions[enum_type.name] = enum_type
      return self._defined_types.setdefault(type_die, enum_type)

    elif type_die.tag == 'DW_TAG_subroutine_type':
      function_name = self.get_type_name(type_die, alias)
      if function_name is None:
        function_name = QualifiedName()
      if has_type(type_die):
        visited.append(type_die)
        return_type = self._make_user_type_helper(self.type_of(type_die), visited=visited)
        visited.pop()
      else:
        return_type = VOID
      function_type = FunctionType(name=function_name, return_type=return_type)
      for param_die in type_die.iter_children():
        if param_die.tag == 'DW_TAG_formal_parameter':
          visited.append(type_die)
          param_type = self._make_user_type_helper(self.type_of(param_die), visited=visited)
          visited.pop()
          function_type.parameters.append(param_type)
        elif param_die.tag == 'DW_TAG_unspecified_parameters':
          function_type.parameters.append(VARIADIC)
        else:
          self._logger.warning((
            f'While defining subroutine type "{function_name}", '
            f'encountered an unhandled tag "{param_die.tag}"'))
      if function_type.name:
        if function_type.name in self._definitions:
          return self._definitions[function_type.name]
        else:
          self._definitions[function_type.name] = function_type
      return self._defined_types.setdefault(type_die, function_type)

    elif type_die.tag == 'DW_TAG_array_type':
      array_name = self.get_type_name(type_die, alias)
      element_die = self._dwarf_db.get_type_attr_as_die(type_die)
      if element_die is None:
        raise Exception('DW_TAG_array_type has no type DIE')
      visited.append(type_die)
      element_type = self._make_user_type_helper(element_die, visited=visited)
      visited.pop()
      array_count = self._dwarf_db.get_array_count(type_die)
      if array_count is None:
        array_count = 0
      array_type = ArrayType(element_type=element_type, count=array_count, name=array_name)
      if array_type.name:
        if array_type.name in self._definitions:
          return self._definitions[array_type.name]
        else:
          self._definitions[array_type.name] = array_type
      return self._defined_types.setdefault(type_die, array_type)

    elif type_die.tag in ['DW_TAG_restrict_type']:
      restricted_type_die = self._dwarf_db.get_type_attr_as_die(type_die)
      if restricted_type_die is None:
        raise Exception('DW_TAG_restrict_type has no type DIE')
      visited.append(type_die)
      ty = self._make_user_type_helper(restricted_type_die, visited=visited)
      visited.pop()
      return ty

    elif type_die.tag in ['DW_TAG_ptr_to_member_type']:
      p2m_name = self.get_type_name(type_die, alias)
      if has_type(type_die):
        member_type_die = self._dwarf_db.get_type_attr_as_die(type_die)
        assert(member_type_die)
        visited.append(type_die)
        member_type = self._make_user_type_helper(member_type_die, visited=visited)
        visited.pop()
      else:
        member_type = VOID
      if 'DW_AT_containing_type' in type_die.attributes:
        containing_die = self._dwarf_db.get_attr_as_die(type_die, 'DW_AT_containing_type')
        assert(containing_die)
        visited.append(type_die)
        containing_type = self._make_user_type_helper(containing_die, visited=visited)
        visited.pop()
        assert(isinstance(containing_type, CompositeType))
      else:
        containing_type = StructType()
      p2m_type = PointerToMemberType(name=p2m_name, container=containing_type, target=member_type)
      return p2m_type

    elif type_die.tag == 'DW_TAG_string_type':
      assert('DW_AT_type' not in type_die.attributes)
      if 'char' not in self._base_types:
        char_type = BaseType('char', 1)
        self._base_types[str(char_type.name)] = char_type
      else:
        char_type = self._base_types['char']

      if 'DW_AT_byte_size' in type_die.attributes:
        size = type_die.attributes['DW_AT_byte_size'].value
        assert(char_type.byte_size)
        array_type = StringType(char_size=char_type.byte_size, is_null_terminated=False, byte_size=size)
        return self._defined_types.setdefault(type_die, array_type)
      else:
        cptr_type = PointerType(self._addr_size, target_type=char_type)
        return self._defined_types.setdefault(type_die, cptr_type)

    elif type_die.tag == 'DW_TAG_subrange_type':
      assert('DW_AT_type' in type_die.attributes)
      subrange_type = self._dwarf_db.get_type_attr_as_die(type_die)
      assert(subrange_type)
      visited.append(type_die)
      ty = self._make_user_type_helper(subrange_type, visited=visited)
      visited.pop()
      return ty

    elif type_die.tag == 'DW_TAG_variant_part':
      return VOID

    else:
      print(type_die)
      assert(type_die and False)

  def get_type_name(self, type_die: DIE, alias: Optional[QualifiedName] = None):
    if 'DW_AT_name' in type_die.attributes:
      return self._dwarf_db.get_qualified_name(type_die)
    else:
      if alias is None:
        return QualifiedName()
      else:
        return alias

  def member_offset_of(self, die: DIE) -> Optional[int]:
    if 'DW_AT_data_member_location' in die.attributes:
      attr = die.attributes['DW_AT_data_member_location']
      if attr.form in ['DW_FORM_data1', 'DW_FORM_data2', 'DW_FORM_data4', 'DW_FORM_data8', 'DW_FORM_udata', 'DW_FORM_sdata']:
        return attr.value
      elif attr.form in ['DW_FORM_block1']:
        self._expr_parser.clear()
        self._expr_parser.parse(attr.value)
        s = self._expr_parser.stack
        if len(s) == 2 and s[0] == ExprOp.PLUS_IMM:
          if isinstance(s[1], int):
            return s[1]
        return None
      elif attr.form in ['DW_FORM_exprloc']:
        self._expr_parser.clear()
        self._expr_parser.parse(attr.value)
        s = self._expr_parser.stack
        if len(s) == 2 and s[0] == ExprOp.PLUS_IMM:
          if isinstance(s[1], int):
            return s[1]
        return None
      else:
        print(attr)
        raise NotImplementedError(f'unsupported attr form ({attr.form}) for DW_AT_data_member_location')
    else:
      return None


class LocationFactory(object):
  def __init__(self, dwarf_db: DWARFDB):
    self._dwarf_db = dwarf_db
    structs = self._dwarf_db._pri._dwarf_info.structs
    arch = self._dwarf_db._pri._arch
    self._expr_parser = LocExprParser(structs, arch)
    self._memo = dict()

  def make_location(self, begin: int, end: int, loc_expr) -> Optional[Location]:
    if not isinstance(loc_expr, tuple):
      loc_expr = tuple(loc_expr)
    if loc_expr in self._memo:
      ty, expr = self._memo[loc_expr]
    else:
      self._expr_parser.clear()
      self._expr_parser.parse(loc_expr)
      if self._expr_parser.location_type is None:
        return None
      expr = tuple(self._expr_parser.stack)
      ty = self._expr_parser.location_type
      self._memo[loc_expr] = (ty, expr)
    return Location(begin=begin, end=end, type=ty, expr=expr)


def import_ELF_DWARF_into_model(elf_file: ELFFile, model: AnalysisModel, query=dict(), debug_root: Optional[str] = None, logger=None):
  dwarf_db = DWARFDB(elf_file, debug_root)
  importer = DWARFImporter(dwarf_db, query, model, logger)
  importer.import_debug_info()


def import_ELF_DWARF(file: Union[str, bytes, int], query=dict()) -> AnalysisModel:
  elf_file = ELFFile(open(file, 'rb'))
  if elf_file.has_dwarf_info():
    model = AnalysisModel('')
    import_ELF_DWARF_into_model(elf_file, model)
    return model
  raise Exception('ELF has no DWARF info')


def ELF_has_debug_info(elf_file) -> bool:
  if elf_file.get_section_by_name('.debug_info') or elf_file.get_section_by_name('.zdebug_info'):
    return True
  else:
    return False

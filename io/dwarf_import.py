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

import os
import sys
import elftools
import logging
import pathlib
import os.path as path
from enum import Enum, auto
from collections import defaultdict
from itertools import chain, tee
from typing import Mapping, List, Generator, Set, Optional, Union, Tuple, Any
from elftools.elf.elffile import ELFFile
from elftools.common.py3compat import (ifilter, byte2int, bytes2str, itervalues, str2bytes, iterbytes)
from elftools.dwarf.dwarfinfo import DWARFInfo
from elftools.dwarf.compileunit import CompileUnit
from elftools.dwarf.descriptions import (describe_DWARF_expr, set_global_machine_arch, describe_reg_name)
from elftools.dwarf.constants import (DW_LNS_copy, DW_LNS_set_file, DW_LNE_define_file)
from elftools.dwarf.dwarf_expr import GenericExprVisitor
from elftools.dwarf.die import AttributeValue, DIE
from elftools.dwarf.locationlists import LocationEntry, BaseAddressEntry
from dwarf_import.model import Module
from dwarf_import.model.elements import (
  Component, ComponentOrigin, Element,
  ImportedModule, ImportedFunction,
  Function, LocalVariable, LocationType, Location, Parameter,
  Variable,
  Constant,
  Type, CompositeType, ScalarType
)


def partition(items, predicate=bool):
  a, b = tee((predicate(item), item) for item in items)
  return ((item for pred, item in a if pred), (item for pred, item in b if not pred))


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


from .dwarf_expr import ExprEval, LocExprParser


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


def member_offset_of(die: DIE) -> Optional[int]:
  """Returns the static offset of the member, if available.
  """
  if 'DW_AT_data_member_location' in die.attributes:
    attr = die.attributes['DW_AT_data_member_location']
    if attr.form in ['DW_FORM_data1', 'DW_FORM_data2', 'DW_FORM_data4', 'DW_FORM_data8', 'DW_FORM_udata']:
      return attr.value
    elif attr.form in ['DW_FORM_exprloc', 'DW_FORM_block1']:
      return None
    else:
      print(attr.form)
      assert(False)
      return attr.value
  else:
    return None


class UnresolvableDIEError(Exception):
  def __init__(self, source_die, attribute_name):
    self.source_die = source_die
    self.attribute_name = attribute_name

  def __str__(self):
    return f'Unable to resolve the DIE specified by the "{self.attribute_name}" attribute in {self.source_die}'

  def __repr__(self):
    return f'<UnresolvableDIEError: {self.attribute_name}>'


class DWARFData(object):
  def __init__(self, elf_file: ELFFile, debug_root: str = None):
    self._elf_file = elf_file
    self._debug_root = debug_root
    self._arch = elf_file.get_machine_arch()
    self._dwarf_info = elf_file.get_dwarf_info()
    self._range_lists = self._dwarf_info.range_lists()
    self._location_lists = self._dwarf_info.location_lists()
    self._die_map = dict()
    self._line_programs = dict()
    self._debug_str = None
    self._logger = logging.getLogger('DWARFData')
    self._index()

  def _index(self):
    for cu in self._dwarf_info.iter_CUs():
      self._die_map.update({die.offset: die for die in cu.iter_DIEs()})

  def get_alt_filename(self) -> Optional[str]:
    section = self._elf_file.get_section_by_name('.gnu_debugaltlink')
    if section is None:
      return None
    b: bytes = section.data()
    end = b.find(0)
    alt_filename = b[:end].decode('utf-8')
    if alt_filename[0] == '/':
      alt_filename = alt_filename[1:]
    alt_filename = os.path.join(self._debug_root, alt_filename)
    return alt_filename

  def iter_compile_units(self) -> Generator[DIE, None, None]:
    return filter(lambda die: die.tag == 'DW_TAG_compile_unit', map(lambda cu: cu.get_top_DIE(), self._dwarf_info.iter_CUs()))

  def iter_section_starts(self) -> Generator[int, None, None]:
    return filter(lambda addr: addr > 0, map(lambda section: section['sh_addr'], self._elf_file.iter_sections()))

  def get_die_at_offset(self, offset) -> DIE:
    if offset not in self._die_map:
      raise ValueError(f'offset ({offset}) not in DIE map')
    return self._die_map[offset]

  def get_location_list(self, ll_offset) -> List[Union[LocationEntry, BaseAddressEntry]]:
    return self._location_lists.get_location_list_at_offset(ll_offset)

  def get_line_program(self, die: DIE):
    memo_key = die.cu.cu_die_offset
    if memo_key in self._line_programs:
      return self._line_programs[memo_key]
    line_program = self._dwarf_info.line_program_for_CU(die.cu)
    return self._line_programs.setdefault(memo_key, line_program)

  def get_range_list_at_offset(self, offset):
    return self._range_lists.get_range_list_at_offset(offset)

  def get_debug_str_at_offset(self, offset: int):
    if self._debug_str is None:
      section = self._elf_file.get_section_by_name('.debug_str')
      assert(section != None)
      self._debug_str = section.data()

    end = self._debug_str.find(0, offset)
    if end == -1:
      end = len(b)
    b = self._debug_str[offset:end]
    return b.decode('utf-8')


class DWARFDB(object):
  REFERENCE_FORMS = set(['DW_FORM_ref1', 'DW_FORM_ref2', 'DW_FORM_ref4', 'DW_FORM_ref8', 'DW_FORM_ref_addr', 'DW_FORM_ref_sig8', 'DW_FORM_ref_sup4', 'DW_FORM_ref_sup8'])

  def __init__(self, elf_file: ELFFile, debug_root: str = None):
    self._logger = logging.getLogger('DWARFDB')
    self._base_addresses = dict()
    self._pri = DWARFData(elf_file, debug_root)
    self._sup = None
    sup_filename = self._pri.get_alt_filename()
    if sup_filename:
      self._sup = DWARFData(ELFFile(open(os.path.join(debug_root, sup_filename), 'rb')))
    # self._index_dwarf_data()

  def _index_dwarf_data(self):
    # Iterate over the compilation units.
    # for top_die in map(lambda cu: cu.get_top_DIE(), self._pri.iter_compile_units()):
    for top_die in self._pri.iter_compile_units():
      self.process_imported_units(top_die)

  def process_imported_units(self, unit_die: DIE):
    """Include nested partial units.
    """
    # self._logger.debug(f'Importing unit at {unit_die.cu.cu_offset}')
    for child in unit_die.iter_children():
      if child.tag == 'DW_TAG_imported_unit':
        imported_unit_die = self.get_attr_as_die(child, 'DW_AT_import')
        if imported_unit_die is not None:
          self.process_imported_units(imported_unit_die)

  def iter_compile_units(self) -> Generator[DIE, None, None]:
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
      else:
        return self._sup.get_die_at_offset(attr_value.value + attr_die.cu.cu_offset)
    elif attr_value.form == 'DW_FORM_ref_addr':
      if attr_die.cu.dwarfinfo == self._pri._dwarf_info:
        return self._pri.get_die_at_offset(attr_value.value)
      else:
        return self._sup.get_die_at_offset(attr_value.value)
    elif attr_value.form == 'DW_FORM_GNU_ref_alt':
      return self._sup.get_die_at_offset(attr_value.value)
    else:
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

  def get_qualified_name(self, die: DIE) -> Union[str, Tuple[str]]:
    if die._parent is not None and die._parent.tag in ('DW_TAG_structure_type', 'DW_TAG_class_type', 'DW_TAG_interface_type', 'DW_TAG_union_type', 'DW_TAG_namespace'):
      qname = self.get_qualified_name(die._parent)
      uname = self.get_name(die) if has_name(die) else 'anonymous'
      if isinstance(qname, tuple):
        return (*qname, uname)
      elif qname is not None:
        return (qname, uname)
      else:
        return uname
    else:
      return self.get_name(die)

  def get_name(self, die: DIE) -> Optional[str]:
    return self.get_attr_as_string(die, 'DW_AT_name')

  def get_start_address(self, die: DIE) -> Optional[int]:
    if 'DW_AT_entry_pc' in die.attributes:
      return die.attributes['DW_AT_entry_pc'].value
    if 'DW_AT_low_pc' in die.attributes:
      return die.attributes['DW_AT_low_pc'].value
    if 'DW_AT_ranges' in die.attributes:
      if die.cu.dwarfinfo == self._pri._dwarf_info:
        ranges = self._pri.get_range_list_at_offset(die.attributes['DW_AT_ranges'].value)
      else:
        ranges = self._alt.get_range_list_at_offset(die.attributes['DW_AT_ranges'].value)
      for r in ranges:
        if type(r) == elftools.dwarf.ranges.BaseAddressEntry:
          return r.base_address
        else:
          return r.begin_offset
    # self._logger.debug(f'unable to determine the start address\n{die}')
    return None

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

  def is_concrete_variable(self, die):
    return any(map(lambda attr_name: attr_name in CONCRETE_SUBPROGRAM_ATTRIBUTES, die.attributes.keys()))

  def get_decl_file(self, die: DIE) -> Optional[str]:
    file_id = self.get_attr_as_int(die, 'DW_AT_decl_file')
    if file_id != None:
      file_index = file_id - 1
      if file_index >= 0:
        line_program = self._pri.get_line_program(die)
        filename = line_program['file_entry'][file_index]['name'].decode('utf-8')
        return filename
    return None

  def get_attr_as_location_list(self, die: DIE, attr_name: str) -> Optional[List[Union[LocationEntry, BaseAddressEntry]]]:
    result = self.get_attribute(die, attr_name)
    if result is None:
      return None

    loc_die, loc_attr = result
    if loc_attr.form in ['DW_FORM_exprloc', 'DW_FORM_block1']:
      return [LocationEntry(begin_offset=0, end_offset=0, loc_expr=loc_attr.value)]
    elif loc_attr.form == 'DW_FORM_sec_offset':
      base = self.get_cu_base_address(loc_die.cu)
      locations = []
      assert(loc_die.cu.dwarfinfo == self._pri._dwarf_info)
      for entry in self._pri.get_location_list(loc_attr.value):
        if isinstance(entry, LocationEntry):
          locations.append(LocationEntry(begin_offset=base+entry.begin_offset, end_offset=base+entry.end_offset, loc_expr=entry.loc_expr))
        elif isinstance(entry, BaseAddressEntry):
          base = entry.base_address
        else:
          assert(False)
      return locations

    elif loc_attr.form == 'DW_FORM_data4':
      base = self.get_cu_base_address(loc_die.cu)
      locations = []
      assert(loc_die.cu.dwarfinfo == self._pri._dwarf_info)
      for entry in self._pri.get_location_list(loc_attr.value):
        if isinstance(entry, LocationEntry):
          # print(hex(entry.begin_offset), hex(entry.end_offset), entry.loc_expr)
          if base is None:
            locations.append(LocationEntry(begin_offset=entry.begin_offset, end_offset=entry.end_offset, loc_expr=entry.loc_expr))
          else:
            locations.append(LocationEntry(begin_offset=base+entry.begin_offset, end_offset=base+entry.end_offset, loc_expr=entry.loc_expr))
        elif isinstance(entry, BaseAddressEntry):
          base = entry.base_address
        else:
          assert(False)
      return locations

    else:
      self._logger.error(f'unhandled location form {loc_attr.form}')

    assert(False)
    return None

  def get_location_list(self, die: DIE) -> List[Union[LocationEntry, BaseAddressEntry]]:
    result = self.get_attr_as_location_list(die, 'DW_AT_location')
    return result if result != None else ()

  def get_cu_base_address(self, cu: CompileUnit) -> Optional[int]:
    base = self._base_addresses.get(cu, None)
    if base == None:
      base = self._base_addresses.setdefault(cu, self.get_start_address(cu.get_top_DIE()))
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
          return ub + 1  # TODO: assuming zero-based, but need to know for sure
    return None


def qualified_name_to_str(qname: Union[Tuple[str], str]):
  return '::'.join(qname) if isinstance(qname, tuple) else qname


class DWARFImporter(object):
  def __init__(self, dwarf_db: DWARFDB, query):
    self._dwarf_db = dwarf_db
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
    self._include_subprogram_decls = query.get('include_subprogram_decls', False)
    self._compile_unit_filter = query.get('cu_filter', None)
    self._die_map = dict()
    # self._line_programs = dict()
    # self._imported_types: Mapping[DIE, Type] = dict()
    self._imported_subprograms: Mapping[str, Set[str]] = defaultdict(set)
    self._logger = logging.getLogger('DWARFImporter')

  def import_components(self) -> Generator[Component, None, None]:
    for cu_die in self._dwarf_db.iter_compile_units():
      name = self._dwarf_db.get_name(cu_die)
      if self._compile_unit_filter and name not in self._compile_unit_filter:
        continue

      self._type_factory.clear()
      self._imported_subprograms = defaultdict(set)
      self._base_address = self._dwarf_db.get_start_address(cu_die)

      self._logger.debug('--'+(name.ljust(78, '-') if name else ''))
      component = Component(name)
      component.origin = ComponentOrigin.SOURCE
      self.import_from_compile_unit(cu_die, component)

      # Create an import group for each decl_file.  Put the external subprograms into their respective group.
      for decl_file, subprogram_names in self._imported_subprograms.items():
        g = ImportedModule(name=decl_file)
        g.add_functions([ImportedFunction(name=name) for name in subprogram_names])
        component.add_imported_modules(g)
      component.add_types(self._type_factory.iter_types())
      yield component

  def import_from_compile_unit(self, die: DIE, component: Component):
    for child in die.iter_children():
      if child.tag == 'DW_TAG_subprogram':
        if self._include_subprograms:
          self.import_subprogram(child, component)
      elif child.tag == 'DW_TAG_variable':
        if self._include_variables:
          self.import_global_variable(child, component)
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
        self.import_from_compile_unit(child, component)
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
          'DW_TAG_imported_declaration',
          'DW_TAG_dwarf_procedure',
          'DW_TAG_constant'
      ]:
        pass
      else:
        print(child.tag, '(child tag)')

  def import_global_variable(self, die: DIE, component: Component) -> Optional[Variable]:
    if 'DW_AT_declaration' in die.attributes:
      return None
    locations = self._dwarf_db.get_location_list(die)
    if locations is None:
      constant = self._dwarf_db.get_attr_as_constant(die, 'DW_AT_const_value')
      if constant is None:
        return None

    qname = self._dwarf_db.get_qualified_name(die)
    if qname is None:
      print(die)
    if not self._globals_filter(qname):
      return None
    name = qualified_name_to_str(qname)
    assert(name is not None)
    # name = '::'.join(qname) if isinstance(qname,tuple) else qname
    self._logger.debug(f'variable {name}')
    var_type = self._type_factory.make_user_type(self._dwarf_db.get_type_attr_as_die(die))

    if locations != None:
      address = None
      for begin, end, loc_expr in locations:
        loc = self._location_factory.make_location(begin, end, loc_expr)
        if loc and loc.type == LocationType.STATIC_GLOBAL:
          address = loc.expr[0]
          assert(isinstance(address, int))
          break
      if address is None:
        v = Variable(name=name, start=None, type=var_type)
        component.add_variables(v)
        return v
      if address >= self._min_section_addr:
        v = Variable(name=name, start=address, type=var_type)
        component.add_variables(v)
        return v
    elif constant != None:
      c = Constant(name=name, type=var_type)
      c.value = constant
      component.add_constants(c)
      return None

  def import_imported_declaration(self, die: DIE):
    import_die = self._dwarf_db.get_attr_as_die(die, 'DW_AT_import')
    if import_die is None:
      return
    qname = self._dwarf_db.get_qualified_name(import_die)
    name = qualified_name_to_str(qname)
    self._imported_subprograms[self._dwarf_db.get_decl_file(die)].add(name)

  def import_location_list(self, location_list):
    if location_list is None:
      return None
    locations = []
    for loc in location_list:
      r = self._location_factory.make_location(loc.begin_offset, loc.end_offset, loc.loc_expr)
      if r != None:
        locations.append(r)
    if len(locations) == 1:
      return locations[0]
    elif len(locations) == 0:
      return None
    else:
      return locations

  def import_subprogram(self, die: DIE, component: Component):
    is_concrete = self._dwarf_db.is_concrete_subprogram(die)
    if self._only_concrete_subprograms and not is_concrete:
      return
    qname = self._dwarf_db.get_qualified_name(die)
    if not self._globals_filter(qname):
      return
    name = qualified_name_to_str(qname)
    self._logger.debug(f'subprogram {name}')
    start = self._dwarf_db.get_start_address(die) if is_concrete else None
    function = Function(name=name, start=start)
    function.return_type = self._type_factory.make_user_type(self._dwarf_db.get_type_attr_as_die(die))
    function.no_return = True if self._dwarf_db.get_attribute(die, 135) else False
    function.frame_base = self.import_location_list(self._dwarf_db.get_attr_as_location_list(die, 'DW_AT_frame_base'))
    if self._include_subprogram_decls:
      decl_file = self._get_decl_file(die)
      if decl_file is not None:
        function.set_attribute('decl_file', decl_file)
    location_map = defaultdict(list)
    abstract_map = dict()
    self.import_local_elements(die, component, function, None, location_map=location_map, abstract_map=abstract_map)
    self.apply_variable_hiding(location_map)
    component.add_variables(self.extract_global_variables(function))
    component.add_functions(function)

  def extract_global_variables(self, function: Function):
    """Extract function variables with global storage (e.g., static) """
    for v in function.variables:
      global_locations = list(loc for loc in v.locations if loc.type == LocationType.STATIC_GLOBAL)
      if global_locations:
        for g in global_locations:
          yield Variable(name=v.name, start=g.expr[0], type=v.type)
          v.locations.remove(g)

  def apply_variable_hiding(self, location_map):
    """
        param < variable < inlined param < inlined variable
    """
    for loc, elements in location_map.items():
      if len(elements) > 1:
        # print(loc, elements)
        # Find the most recent element whose type differs from a preceding element.
        j = None
        for i in range(len(elements)-1, 0, -1):
          if elements[i].type != elements[i-1].type:
            j = i
            break
        if j is None:
          continue
        # Find the next non-artificial element.
        while j < len(elements)-1 and elements[j].name in ['this', '__artificial__']:
          j += 1
        # Remove the location from the prior elements.
        for i in range(0, j):
          elements[i].locations.remove(loc)

  def import_inlined_subroutine(self, die: DIE, component: Component, parent_function: Function, location_map, abstract_map):
    qname = self._dwarf_db.get_qualified_name(die)
    name = qualified_name_to_str(qname)
    self._logger.debug(f'inlined subroutine {name}')
    start = self._dwarf_db.get_start_address(die)
    function = Function(name=name, start=start)
    function.return_type = self._type_factory.make_user_type(self._dwarf_db.get_type_attr_as_die(die))
    function.frame_base = self.import_location_list(self._dwarf_db.get_attr_as_location_list(die, 'DW_AT_frame_base'))
    self.import_local_elements(die, component, function, parent_function, location_map=location_map, abstract_map=abstract_map)
    return function

  def import_local_elements(self, die: DIE, component: Component, function: Function, parent_function: Function, inside_lexical_block: bool = False, location_map = None, abstract_map=None):
    """Imports function elements.

    Notes
    -----
    Local variables can share locations with the formal parameters. For
    example, opaque parameters that are simply type cast to a structure
    pointer occur quite often.  In these cases, we want the local variable
    to take priority over the parameter.  If a variable shares a Location
    with a parameter, that location will be removed from the parameter's
    location list.  In short, the variable hides the parameter at that
    location.

    Also, inlined functions may have parameters or local variables that
    share locations with the containing function's variables and/or
    parameters.  Thus, if the type stored at the location differs from
    the containing function, we use the most specific type - the local
    hides the pre-existing variable from that location.  But if the name
    of the variable or parameter is "artificial" then the artificial
    name is replaced/inherited from the variable that shares the location.
    """
    for child in die.iter_children():
      if child.tag == 'DW_TAG_variable':
        if self._include_local_variables:
          if self._dwarf_db.is_concrete_variable(child):
            local_var = self.import_local_variable(child, component, function, abstract_map)
            if local_var:
              # print(self._dwarf_db.is_concrete_variable(die), child)
              self.import_locations(local_var, child, location_map, [LocationType.STATIC_LOCAL, LocationType.STATIC_GLOBAL])
          # else:
          #     self._logger.warning(f'In {function.name} variable is not concrete\n{child}')
      elif child.tag == 'DW_TAG_formal_parameter':
        if self._include_parameters:
          param = self.import_parameter(child, function, parent_function, abstract_map)
          if param:
            self.import_locations(param, child, location_map, [LocationType.STATIC_LOCAL])
      elif child.tag == 'DW_TAG_unspecified_parameters':
        p = Parameter(name='...', type=None)
        function.add_parameter(p)
      elif child.tag == 'DW_TAG_lexical_block':
        self.import_local_elements(child, component, function, parent_function, inside_lexical_block=True, location_map=location_map, abstract_map=abstract_map)
      elif child.tag == 'DW_TAG_inlined_subroutine':
        if self._include_inlined_functions:
          f = self.import_inlined_subroutine(child, component, function if parent_function is None else parent_function, location_map, abstract_map)
          function.add_inlined_function(f)
      elif child.tag == 'DW_TAG_subprogram':
        if self._dwarf_db.is_concrete_subprogram(child):
          self._logger.warning(f'In {function.name} a concrete subprogram inside subprogram\n{child}')
        else:
          pass
      elif child.tag in [
          'DW_TAG_template_type_parameter',
          'DW_TAG_template_type_param',
          'DW_TAG_template_value_param',
          'DW_TAG_GNU_formal_parameter_pack',
          'DW_TAG_GNU_template_parameter_pack',
          'DW_TAG_GNU_call_site',
          'DW_TAG_label',
          'DW_TAG_imported_declaration',
          'DW_TAG_constant',
          # Types are picked up via the variables, as needed.
          'DW_TAG_typedef',
          'DW_TAG_structure_type',
          'DW_TAG_union_type',
          'DW_TAG_class_type',
          'DW_TAG_interface_type',
          'DW_TAG_const_type',
          'DW_TAG_pointer_type',
          'DW_TAG_enumeration_type'
      ]:
        # TODO: use DW_TAG_label to inform control-flow reconstruction
        pass
      else:
        self._logger.warning(f'unhandled tag {child.tag} inside {die.tag}\n\tParent DIE = {die}\n\tChild DIE  = {child}')

  def import_parameter(self, die: DIE, function: Function, parent_function: Optional[Function], abstract_map):
    if 'DW_AT_abstract_origin' in die.attributes:
      abstract_origin = self._dwarf_db.get_attr_as_die(die, 'DW_AT_abstract_origin')
      if abstract_origin in abstract_map:
        return abstract_map[abstract_origin]

    name = self._get_parameter_name(die)
    if name is None:
      name = ''
      self._logger.debug(f'in {function.name}: unnamed parameter\n{die})')
    if name is not None:
      type_die = self._dwarf_db.get_type_attr_as_die(die)
      if type_die is not None:
        parameter_type = self._type_factory.make_user_type(type_die)
        p = Parameter(name=name, type=parameter_type)
        function.add_parameter(p)

        if 'DW_AT_abstract_origin' in die.attributes:
          abstract_map[abstract_origin] = p

        return p
      else:
        self._logger.error(f'In "{function.name}", parameter "{name}" has no type')
    else:
      self._logger.warning(f'parameter has no name {die}')
      self._logger.warning(f'parameter type {self._type_of(die)}')
      name = 'anonymous'

  def import_locations(self, element: Element, die: DIE, location_map: Mapping[Element, List[Location]], location_filter):
    # print(f'importing for {element}')
    for begin, end, loc_expr in self._dwarf_db.get_location_list(die):
      # print(f'\t\t\t{begin:x} {end:x} {loc_expr}')
      loc = self._location_factory.make_location(begin, end, loc_expr)
      # print(f'\t\t{loc}')
      if loc and loc.type in location_filter:
        element.add_location(loc)
        location_map[loc].append(element)

  def import_local_variable(self, die: DIE, component: Component, fn: Function, abstract_map):
    if 'DW_AT_abstract_origin' in die.attributes:
      abstract_origin = self._dwarf_db.get_attr_as_die(die, 'DW_AT_abstract_origin')
      if abstract_origin in abstract_map:
        return abstract_map[abstract_origin]

    name = self._get_local_variable_name(die)
    if name is None:
      return None

    if fn != None:
      try:
        var_type = self._type_factory.make_user_type(self._dwarf_db.get_type_attr_as_die(die))

        # Check if this variable is actually a constant without a location.
        if 'DW_AT_const_value' in die.attributes and 'DW_AT_location' not in die.attributes:
          c = Constant(name=name, type=var_type, value=die.attributes['DW_AT_const_value'].value)
          fn.add_constant(c)
        else:
          # # TODO: if the location is actually global, then

          v = LocalVariable(name=name, type=var_type)
          fn.add_variable(v)
          if 'DW_AT_abstract_origin' in die.attributes:
            abstract_map[abstract_origin] = v
          return v
      except:
        self._logger.exception("importing local variable", exc_info=sys.exc_info())

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
    self._defined_types: Mapping[DIE, Type] = dict()
    self._base_types: Mapping[str, Type] = dict()
    self._logger = logging.getLogger('TypeFactory')

  def clear(self):
    self._defined_types = dict()

  def iter_types(self) -> Generator[Type, None, None]:
    return self._defined_types.values()

  def name_of(self, die: DIE) -> Optional[str]:
    return self._dwarf_db.get_name(die)

  def type_of(self, die: DIE) -> DIE:
    return self._dwarf_db.get_type_attr_as_die(die)

  def make_user_type(self, type_die: DIE, alias: Optional[str] = None) -> Type:
    visited = []
    return self._make_user_type_helper(type_die, alias, visited)

  def _make_user_type_helper(self, type_die: DIE, alias: Optional[str] = None, visited = None) -> Type:
    """Create a type object to represent the DWARF type.
    """
    if type_die in self._defined_types:
      return self._defined_types[type_die]

    if type_die is None:
      return self._defined_types.setdefault(None, Type.void())

    # Detect cycles in the DIE structures.
    if type_die in visited:
      return Type.void()
    visited.append(type_die)

    if type_die.tag == 'DW_TAG_base_type':
      base_type = Type(scalar_type=ScalarType.BASE_TYPE, name=self.name_of(type_die), size=size_of(type_die))
      self._base_types[base_type.name] = base_type
      return self._defined_types.setdefault(type_die, base_type)

    elif type_die.tag == 'DW_TAG_unspecified_type':
      unspecified_type = Type(scalar_type=ScalarType.BASE_TYPE, name=self.name_of(type_die))
      return self._defined_types.setdefault(type_die, unspecified_type)

    elif type_die.tag == 'DW_TAG_typedef':
      qualified_alias = self._dwarf_db.get_qualified_name(type_die)
      aliased_type_die = self._dwarf_db.get_type_attr_as_die(type_die)
      if type_die:
        element_type = self._make_user_type_helper(aliased_type_die, alias=qualified_alias, visited=visited)
      else:
        element_type = Type.void()
      if element_type.name == qualified_alias:
        return element_type
      else:
        alias = Type(name=qualified_alias, element=element_type)
        return self._defined_types.setdefault(type_die, alias)

    elif type_die.tag in ['DW_TAG_const_type', 'DW_TAG_volatile_type']:
      if has_type(type_die):
        try:
          element_type = self._make_user_type_helper(self.type_of(type_die), visited=visited)
        except Exception as e:
          self._logger.error(str(e))
          raise e
      else:
        element_type = Type.void()
      qualified_type = Type(element=element_type)
      if type_die.tag == 'DW_TAG_const_type':
        qualified_type.is_constant = True
      elif type_die.tag == 'DW_TAG_volatile_type':
        qualified_type.is_volatile = True
      return self._defined_types.setdefault(type_die, qualified_type)

    elif type_die.tag in ['DW_TAG_pointer_type', 'DW_TAG_reference_type', 'DW_TAG_rvalue_reference_type']:
      if has_type(type_die):
        element_type = self._make_user_type_helper(self.type_of(type_die), visited=visited)
      else:
        element_type = Type.void()
      pointer_size = size_of(type_die) if has_size(type_die) else None
      pointer_type = Type(element=element_type, size=pointer_size)
      if type_die.tag == 'DW_TAG_pointer_type':
        pointer_type.scalar_type = ScalarType.POINTER_TYPE
      elif type_die.tag == 'DW_TAG_reference_type':
        pointer_type.scalar_type = ScalarType.REFERENCE_TYPE
      elif type_die.tag == 'DW_TAG_class_type':
        pointer_type.scalar_type = ScalarType.RVALUE_REFERENCE_TYPE
      elif type_die.tag == 'DW_TAG_interface_type':
        pointer_type.scalar_type = ScalarType.RVALUE_REFERENCE_TYPE
      if has_name(type_die):
        # Create a type alias and return that.
        alias_type = Type(name=self.name_of(type_die), element=pointer_type)
        return self._defined_types.setdefault(type_die, alias_type)
      else:
        return self._defined_types.setdefault(type_die, pointer_type)

    elif type_die.tag in ['DW_TAG_structure_type', 'DW_TAG_class_type', 'DW_TAG_union_type', 'DW_TAG_interface_type']:
      composite_name = self.get_type_name(type_die, alias)
      composite_size = size_of(type_die) if has_size(type_die) else None
      composite_type = Type(name=composite_name, size=composite_size)
      if type_die.tag == 'DW_TAG_structure_type':
        composite_type.composite_type = CompositeType.STRUCT_TYPE
      elif type_die.tag == 'DW_TAG_union_type':
        composite_type.composite_type = CompositeType.UNION_TYPE
      elif type_die.tag == 'DW_TAG_class_type':
        composite_type.composite_type = CompositeType.CLASS_TYPE
      elif type_die.tag == 'DW_TAG_interface_type':
        composite_type.composite_type = CompositeType.CLASS_TYPE
      forward_type = Type(name=composite_name, size=composite_size)
      forward_type.composite_type = composite_type.composite_type
      self._defined_types[type_die] = forward_type
      for member_die in type_die.iter_children():
        if member_die.tag == 'DW_TAG_member':
          if not has_type(member_die):
            print(member_die)
          member_type = self._make_user_type_helper(self.type_of(member_die), visited=visited)
          if member_type.name is None:
            member_type = member_type.clone()
          member_offset = member_offset_of(member_die) if has_member_offset(member_die) else 0
          if member_offset is not None:
            if has_name(member_die):
              composite_type.add_member(Type(name=self.name_of(member_die), offset=member_offset, element=member_type))
            else:
              composite_type.add_member(Type(offset=member_offset, element=member_type))
          else:
            if 'DW_AT_const_value' in member_die.attributes:
              # TODO: add constant
              pass
            else:
              # TODO: must be static
              pass
        elif member_die.tag == 'DW_TAG_inheritance':
          member_type_die = self.type_of(member_die)
          member_type = self._make_user_type_helper(member_type_die, visited=visited)
          member_offset = member_offset_of(member_die) if has_member_offset(member_die) else 0
          base_name = 'inherited$'
          if has_name(member_type_die):
            base_name = f'inherited${self.name_of(member_type_die)}'
          composite_type.add_member(Type(name=base_name, offset=member_offset, element=member_type))
        elif member_die.tag == 'DW_TAG_variant_part':
          # TODO: implement
          pass
      self._defined_types[type_die] = composite_type
      return composite_type

    elif type_die.tag in ['DW_TAG_enumeration_type']:
      enum_name = self.get_type_name(type_die, alias)
      enum_size = size_of(type_die) if has_size(type_die) else None
      enum_type = Type(composite_type=CompositeType.ENUM_TYPE, name=enum_name, size=enum_size)
      for member_die in type_die.iter_children():
        if member_die.tag == 'DW_TAG_enumerator':
          offset = member_die.attributes['DW_AT_const_value'].value
          enum_type.add_member(Type(scalar_type=ScalarType.ENUMERATOR_TYPE, name=self.name_of(member_die), offset=offset))
      return self._defined_types.setdefault(type_die, enum_type)

    elif type_die.tag == 'DW_TAG_subroutine_type':
      function_name = self.get_type_name(type_die, alias)
      if has_type(type_die):
        return_type = self._make_user_type_helper(self.type_of(type_die), visited=visited)
      else:
        return_type = Type.void()
      function_type = Type(composite_type=CompositeType.FUNCTION_TYPE, name=function_name, element=return_type)
      ordinal = 0
      for param_die in type_die.iter_children():
        if param_die.tag == 'DW_TAG_formal_parameter':
          param_type = self._make_user_type_helper(self.type_of(param_die), visited=visited)
          function_type.add_member(Type(offset=ordinal, element=param_type))
          ordinal += 1
        elif param_die.tag == 'DW_TAG_unspecified_parameters':
          function_type.add_member(Type(offset=ordinal, element=Type.variadic()))
          ordinal += 1
        else:
          self._logger.warning(f'While defining subroutine type "{function_name}", encountered an unhandled tag "{param_die.tag}"')
      return self._defined_types.setdefault(type_die, function_type)

    elif type_die.tag == 'DW_TAG_array_type':
      array_name = self.get_type_name(type_die, alias)
      element_type = self._make_user_type_helper(self._dwarf_db.get_type_attr_as_die(type_die), visited=visited)
      array_count = self._dwarf_db.get_array_count(type_die)
      array_type = Type(scalar_type=ScalarType.ARRAY_TYPE, name=array_name, element=element_type, array_count=array_count)
      return self._defined_types.setdefault(type_die, array_type)

    elif type_die.tag in ['DW_TAG_restrict_type']:
      return self._make_user_type_helper(self._dwarf_db.get_type_attr_as_die(type_die), visited=visited)

    elif type_die.tag in ['DW_TAG_ptr_to_member_type']:
      p2m_name = self.get_type_name(type_die, alias)
      if has_type(type_die):
        member_type = self._make_user_type_helper(self._dwarf_db.get_type_attr_as_die(type_die), visited=visited)
      else:
        member_type = Type.void()
      if 'DW_AT_containing_type' in type_die.attributes:
        containing_die = self._dwarf_db.get_attr_as_die(type_die, 'DW_AT_containing_type')
        containing_type = self._make_user_type_helper(containing_die, visited=visited)
      else:
        containing_type = Type.void()
      p2m_type = Type(composite_type=CompositeType.PTR_TO_MEMBER_TYPE, name=p2m_name)
      p2m_type.add_member(containing_type)
      p2m_type.add_member(member_type)
      return p2m_type

    elif type_die.tag == 'DW_TAG_string_type':
      assert('DW_AT_type' not in type_die.attributes)
      if 'char' not in self._base_types:
        char_type = Type(scalar_type=ScalarType.BASE_TYPE, name='char', size=1)
        self._base_types[char_type.name] = char_type
      else:
        char_type = self._base_types['char']

      if 'DW_AT_byte_size' in type_die.attributes:
        # Treat it as a char array of fixed length.
        size = type_die.attributes['DW_AT_byte_size'].value
        array_type = Type(scalar_type=ScalarType.ARRAY_TYPE, element=char_type, array_count=size)
        return self._defined_types.setdefault(type_die, array_type)
      else:
        # Treat it a char *.
        cptr_type = Type(scalar_type=ScalarType.POINTER_TYPE, element=char_type)
        return self._defined_types.setdefault(type_die, cptr_type)

    elif type_die.tag == 'DW_TAG_subrange_type':
      assert('DW_AT_type' in type_die.attributes)
      return self._make_user_type_helper(self._dwarf_db.get_type_attr_as_die(type_die), visited=visited)

    elif type_die.tag == 'DW_TAG_variant_part':
      return None

    else:
      print(type_die)
      assert(type_die and False)

  def get_type_name(self, type_die: DIE, alias: str = None) -> str:
    return self._dwarf_db.get_qualified_name(type_die) if 'DW_AT_name' in type_die.attributes else alias


class LocationFactory(object):
  def __init__(self, dwarf_db: DWARFDB):
    self._dwarf_db = dwarf_db
    structs = self._dwarf_db._pri._dwarf_info.structs
    arch = self._dwarf_db._pri._arch
    self._expr_parser = LocExprParser(structs, arch)
    self._memo = dict()

  def make_location(self, begin: int, end: int, loc_expr: List[int]) -> Optional[Location]:
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


def place_component_in_module_tree(root_module: Module, component: Component):
  file_path = pathlib.Path(path.normpath(component.name))
  path_parts = file_path.parts
  m = root_module
  for part in path_parts[:-1]:
    if part in ['..', '/']:
      continue
    child = m.get_submodule(part)
    if child is None:
      m = m.add_submodule(Module(name=part))
    else:
      m = child
  component.name = path_parts[-1]
  m.add_component(component)


def import_ELF_DWARF_into_module(elf_file: ELFFile, module: Module, query = dict(), debug_root: str = None):
  dwarf_db = DWARFDB(elf_file, debug_root)
  importer = DWARFImporter(dwarf_db, query)
  for component in importer.import_components():
    place_component_in_module_tree(module, component)


def create_module_from_ELF_DWARF_file(file: Union[str, bytes, int], query = dict()) -> Optional[Module]:
  elf_file = ELFFile(open(file, 'rb'))
  if elf_file.has_dwarf_info():
    module = Module()
    import_ELF_DWARF_into_module(elf_file, module)
    return module
  else:
    return None

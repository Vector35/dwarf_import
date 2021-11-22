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

import binaryninja as bn
from .bridge import BinjaBridge
from .mapped_model import AnalysisSession
from elftools.elf.elffile import ELFFile
import os


class DWARF_loader(bn.BackgroundTaskThread):
  def __init__(self, bv, debug_file=None):
    bn.BackgroundTaskThread.__init__(self)
    self.view = bv
    self.debug_file = debug_file
    self.progress = ""

  def run(self):
    # Open the binary.
    analysis_session = AnalysisSession(binary_view = self.view, debug_file = self.debug_file)

    if analysis_session.binary_view is None or analysis_session.binary_view.arch is None:
      bn.log.log_error("Unable to import dwarf")

    # Setup the translator.
    bridge = BinjaBridge(analysis_session)
    bridge.translate_model()

    # Finalize the analysis.
    analysis_session.binary_view.update_analysis()


def load_symbols(bv):
  try:
    if bv.query_metadata("dwarf_info_applied") == 1:
      bn.log.log_warn("DWARF Debug Info has already been applied to this binary view")
      return
  except KeyError:
    bv.store_metadata("dwarf_info_applied", True)
  DWARF_loader(bv).start()


def load_symbols_from_file(bv):
  try:
    if bv.query_metadata("dwarf_info_applied") == 1:
      bn.log.log_warn("DWARF Debug Info has already been applied to this binary view")
      return
  except KeyError:
    bv.store_metadata("dwarf_info_applied", True)

  file_choice = bn.interaction.OpenFileNameField("Debug file")
  bn.interaction.get_form_input([file_choice], "Open debug file")

  if not os.path.exists(file_choice.result):
    bn.log.log_error(f"Input file `{file_choice.result}` does not exist")
    return

  DWARF_loader(bv, file_choice.result).start()


def is_valid(bv):
  raw = False
  elf = False
  for view in bv.file.raw.available_view_types:
    if view.name == "ELF":
      raw = True
    elif view.name == "Raw":
      elf = True
  return raw and elf and ELFFile(bn.binaryview.BinaryReader(bv.file.raw)).has_dwarf_info()


bn.PluginCommand.register("DWARF Import\Load DWARF Symbols", "Load DWARF Symbols from the current file", load_symbols, is_valid)
bn.PluginCommand.register("DWARF Import\Load DWARF Symbols From File", "Load DWARF Symbols from another file", load_symbols_from_file, lambda bv: True)

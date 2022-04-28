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

from binaryninja import BackgroundTaskThread
from binaryninja.binaryview import BinaryReader
from binaryninja.log import log_error, log_warn
from binaryninja.interaction import OpenFileNameField, get_form_input
from binaryninja.plugin import PluginCommand
from .bridge import BinjaBridge
from .mapped_model import AnalysisSession
from elftools.elf.elffile import ELFFile
import os


class DWARF_loader(BackgroundTaskThread):
  def __init__(self, bv, debug_file=None):
    BackgroundTaskThread.__init__(self)
    self.view = bv
    self.debug_file = debug_file
    self.progress = ""

  def run(self):
    # Open the binary.
    analysis_session = AnalysisSession(binary_view = self.view, debug_file = self.debug_file)

    if analysis_session.binary_view is None or analysis_session.binary_view.arch is None:
      log_error("Unable to import dwarf")

    # Setup the translator.
    bridge = BinjaBridge(analysis_session)
    bridge.translate_model()

    # Finalize the analysis.
    analysis_session.binary_view.update_analysis()


def load_symbols(bv):
  try:
    if bv.query_metadata("dwarf_info_applied") == 1:
      log_warn("DWARF Debug Info has already been applied to this binary view")
      return
  except KeyError:
    bv.store_metadata("dwarf_info_applied", True)
  DWARF_loader(bv).start()


def load_symbols_from_file(bv):
  try:
    if bv.query_metadata("dwarf_info_applied") == 1:
      log_warn("DWARF Debug Info has already been applied to this binary view")
      return
  except KeyError:
    bv.store_metadata("dwarf_info_applied", True)

  file_choice = OpenFileNameField("Debug file")
  get_form_input([file_choice], "Open debug file")

  if not file_choice.result or os.path.exists(file_choice.result):
    log_error(f"Input file `{file_choice.result}` does not exist")
    return

  DWARF_loader(bv, file_choice.result).start()


def is_valid(bv):
  raw = False
  elf = False
  if not bv.parent_view:
    return False
  for view in bv.parent_view.available_view_types:
    if view.name == "ELF":
      elf = True
    elif view.name == "Raw":
      raw = True
  return raw and elf and ELFFile(BinaryReader(bv.file.raw)).has_dwarf_info()


PluginCommand.register("DWARF Import\\Load DWARF Symbols", "Load DWARF Symbols from the current file", load_symbols, is_valid)
PluginCommand.register("DWARF Import\\Load DWARF Symbols From File", "Load DWARF Symbols from another file", load_symbols_from_file, lambda bv: True)

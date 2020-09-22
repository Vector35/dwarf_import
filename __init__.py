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
from .mapping import MappedModel
from elftools.elf.elffile import ELFFile


class DWARF_loader(bn.BackgroundTaskThread):
  def __init__(self, bv):
    bn.BackgroundTaskThread.__init__(self)
    self.view = bv
    self.file = bv.file
    self.progress = ""

  def run(self):
    # Open the binary.
    mapped_model = MappedModel(binary_view = self.view)
    if mapped_model.binary_view is None or mapped_model.binary_view.arch is None:
      bn.log.log_error("Unable to import dwarf")

    # Setup the translator.
    bridge = BinjaBridge(mapped_model)
    bridge.import_debug_info()

    # Finalize the analysis.
    mapped_model.binary_view.update_analysis()


def load_symbols(bv):
  DWARF_loader(bv).start()


def is_valid(bv):
  raw = False
  elf = False
  for view in bv.file.raw.available_view_types:
    if view.name == "ELF":
      raw = True
    elif view.name == "Raw":
      elf = True
  return raw and elf and ELFFile(bn.binaryview.BinaryReader(bv.file.raw)).has_dwarf_info()


bn.PluginCommand.register("DWARF Import", "Load DWARF Symbols", load_symbols, is_valid)

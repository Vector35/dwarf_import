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

from typing import Any, Optional, Mapping, List
import os
from binaryninja import BinaryView, BinaryViewType
from .model.analysis_model import AnalysisModel
from .mapping import BinjaMap


class AnalysisSession(object):
  def __init__(
      self,
      filename: Optional[str] = None,
      debug_root: Optional[str] = None,
      debug_file: Optional[str] = None,
      binary_view: Optional[BinaryView] = None,
      logger=None
  ):
    if filename is None and binary_view is None:
      raise ValueError('Must specify either a filename or binary view.')

    self.model: AnalysisModel
    self.binary_view: BinaryView
    self.debug_root = debug_root
    self.debug_file = debug_file

    if binary_view is None:
      bv = BinaryViewType.get_view_of_file(filename, update_analysis=True)
      if bv is None:
        raise Exception(f'Unable to get binary view for file: {filename}')
      self.binary_view = bv
    else:
      self.binary_view = binary_view

    if self.binary_view.arch is None:
      raise Exception('The binary view has no valid architecture.')

    # Create the root module with the binary name as the module name.
    if filename is None:
      filename = self.binary_view.file.original_filename
      assert(isinstance(filename, str))
    binary_name = os.path.basename(filename)

    debug_source = filename
    if self.debug_file is not None:
      debug_source = self.debug_file
    m = AnalysisModel.from_dwarf(debug_source, self.debug_root, name=binary_name, logger=logger)
    self.model = m if m else AnalysisModel(binary_name)

    self.mapping = BinjaMap(self.binary_view)

  def __del__(self):
    if hasattr(self, 'binary_view') and self.binary_view is not None:
      self.binary_view.abort_analysis()
      self.binary_view.file.close()
      del self.binary_view

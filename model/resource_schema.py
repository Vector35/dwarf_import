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

from typing import List
from enum import Enum
from .attributes import Attribute
from .concrete_elements import Element


class ResourceType(Enum):
  HEAP_MEMORY = 0
  FILE_OBJECT = 1
  FILE_HANDLE = 2
  NETWORK_SOCKET = 3


class ResourceSchema(object):
  acquires = Attribute('acquires', ResourceType)
  releases = Attribute('releases', ResourceType)
  escapes = Attribute('escapes', bool)
  released_at = Attribute('released_at', List[Element])
  acquired_at = Attribute('acquired_at', List[Element])
  imported = Attribute('imported', bool)
  objects = Attribute('objects', List[Element])

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

from threading import Timer


class Observer(object):
  def __init__(self, dirty_mask, dwell_time=5):
    self.idle_timer = None
    self.dwell_time = dwell_time
    self.dirty_mask = dirty_mask
    self.dirty_flags = set()

  def touch(self, flag):
    if flag in self.dirty_mask:
      if self.idle_timer:
        self.idle_timer.cancel()
      self.dirty_flags.add(flag)
      self.idle_timer = Timer(self.dwell_time, lambda: self.notify_on_idle())
      self.idle_timer.start()

  def notify_on_idle(self):
    flags = self.dirty_flags.copy()
    self.dirty_flags.clear()
    self.on_idle(flags)

  def on_idle(self, flags):
    pass


class Observable(object):
  def __init__(self, parent):
    self._observable_parent = parent
    self._observers = list()

  def add_observer(self, observer):
    self._observers.append(observer)
    # observer.touch(0)

  def remove_observer(self, observer):
    try:
      self._observers.remove(observer)
    except:
      pass

  def remove_all_observers(self):
    self._observers = list()

  def notify(self, event_name, flag, **kwargs):
    for observer in self._observers:
      if self._observable_parent is None:
        observer.touch(flag)
      method = getattr(observer, f'on_{event_name}', None)
      if method:
        method(**kwargs)
    if self._observable_parent:
      self._observable_parent.notify(event_name, flag, **kwargs)

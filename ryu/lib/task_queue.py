# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011, 2012 Isaku Yamahata <yamahata at private email ne jp>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import gevent
import gevent.queue
import logging
import traceback


LOG = logging.getLogger(__name__)


class TaskQueue(object):
    class _TaskClose(object):
        pass

    def __init__(self):
        super(TaskQueue, self).__init__()
        self.is_closed = False
        self.task_q = gevent.queue.Queue()
        self.serve_thread = gevent.spawn(self._serve)

    def close(self):
        self.queue(self._TaskClose)
        self.serve_thread.join()

    def queue(self, func):
        assert not self.is_closed
        self.task_q.put(func)

    def _serve(self):
        try:
            while True:
                func = self.task_q.get()
                if func == self._TaskClose:
                    break
                func()
        except:
            traceback.print_exc()  # for debug
            raise

        # drain queue
        try:
            while True:
                func = self.task_q.get_nowait()
                func()
        except gevent.queue.Empty:
            self.is_closed = True
            pass

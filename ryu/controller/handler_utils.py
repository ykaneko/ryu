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

import logging
import types

from ryu.controller import (dispatcher,
                            event,
                            handler)


LOG = logging.getLogger(__name__)


@classmethod
def _cls_nop(_cls, *_args, **_kwargs):
    pass


def cls_init_once(bound_cls_method, *args, **kwargs):
    bound_cls_method(*args, **kwargs)
    setattr(bound_cls_method.im_self, bound_cls_method.__name__, _cls_nop)


def _cls_set_attr(cls, name, attr):
    if not hasattr(cls, name):
        setattr(cls, name, attr)
    else:
        LOG.warn('already attribute %s is defined', name)


class QueueSerializer(object):
    @classmethod
    def _create_proxy_handlers(cls, ev_clses):
        for (ev, ev_dispatcher) in ev_clses:
            handler_name = 'proxy_%s_%s_handler' % (ev.__name__, ev_dispatcher)
            handler_ = lambda self, ev_: self._ev_q.queue(ev_)
            handler_ = handler.set_ev_cls(ev, ev_dispatcher)(handler_)
            method = types.MethodType(handler_, None, cls)
            _cls_set_attr(cls, handler_name, method)

    def __init__(self, queue_name, ev_dispatcher, ev_clses):
        super(QueueSerializer, self).__init__()
        cls_init_once(self._create_proxy_handlers, ev_clses)
        self._ev_q = dispatcher.EventQueueThread(queue_name, ev_dispatcher)
        handler.register_instance(self)


class RequestQueue(object):
    class _EventRequestBase(event.EventBase):
        def __init__(self, *args):
            super(RequestQueue._EventRequestBase, self).__init__()
            self.args = args

    @classmethod
    def _create_request_methods(cls, dispatcher_name, methods):
        # variable, keyword, default argument aren't supported
        ev_dispatcher = dispatcher.EventDispatcher(dispatcher_name)
        cls._cls_ev_dispatcher = ev_dispatcher

        for method in methods:
            method_name_no_strip = method.__name__
            method_name = method_name_no_strip.lstrip('_')

            # create event class _EventRequest_<method_name>
            ev_cls_name = '_EventRequest_%s' % method_name
            ev_cls = type(ev_cls_name, (cls._EventRequestBase,),
                          dict(__init__=lambda self, *args:
                               super(self.__class__, self).__init__(*args)))
            _cls_set_attr(cls, ev_cls_name, ev_cls)

            # create request_<method_name>(self, <args>) method
            request_func_name = 'request_%s' % method_name
            request_func = eval(
                'lambda self, *args: self._ev_q.queue(self.%s(*args))' %
                ev_cls_name)
            request_method = types.MethodType(request_func, None, cls)
            _cls_set_attr(cls, request_func_name, request_method)

            # create <method_name>_handler(self, <args>) method
            handler_name = '%s_handler' % method_name
            handler_ = eval('lambda self, ev: self.%s(*ev.args)' %
                            method_name_no_strip)
            handler_ = handler.set_ev_cls(ev_cls, ev_dispatcher)(handler_)
            method_ = types.MethodType(handler_, None, cls)
            _cls_set_attr(cls, handler_name, method_)

    def __init__(self, methods):
        super(RequestQueue, self).__init__()

        cls = self.__class__
        postfix = '%s_%x' % (cls.__name__, id(cls))
        queue_name = 'queue_name_%s' % postfix
        dispatcher_name = 'dispatcher_name_%s' % postfix
        cls_init_once(self._create_request_methods, dispatcher_name, methods)
        self._ev_q = dispatcher.EventQueueThread(queue_name,
                                                 self._cls_ev_dispatcher)
        handler.register_instance(self)

    def close(self):
        self._ev_q.close()


def test():
    class RequestQueueTest(RequestQueue):
        def __init__(self):
            _request_methods = (RequestQueueTest.method0,
                                RequestQueueTest.method1,
                                RequestQueueTest.method2)
            super(RequestQueueTest, self).__init__(_request_methods)

        def method0(self):
            print('method0')

        def method1(self, arg0):
            print('method1 arg0 = %s' % arg0)

        def method2(self, arg0, arg1):
            print('method2 arg0 = %s arg1 = %s' % (arg0, arg1))

        def no_method(self):
            print('no_method')

    rqt = RequestQueueTest()
    rqt.method0()
    rqt.method1('a')
    rqt.method2('b', 'c')
    rqt.no_method()

    ev0 = RequestQueueTest._EventRequest_method0()
    rqt.method0_handler(ev0)
    ev1 = RequestQueueTest._EventRequest_method1('A')
    rqt.method1_handler(ev1)
    ev2 = RequestQueueTest._EventRequest_method0('B', 'C')
    rqt.method2_handler(ev2)
    assert not hasattr(rqt, 'no_method_handler')

    rqt.request_method0()
    rqt.request_method1(1)
    rqt.request_method2(2, 3)
    assert not hasattr(rqt, 'request_no_method')

    rqt.close()


if __name__ == '__main__':
    try:
        test()
    except:
        import traceback
        traceback.print_exc()

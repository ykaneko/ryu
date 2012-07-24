# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2012 Isaku Yamahata <yamahata at valinux co jp>
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

from ryu.controller import event
from ryu.controller import dispatcher
from ryu.controller import dp_type
from ryu.controller import handler
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
import ryu.exception as ryu_exc


LOG = logging.getLogger('ryu.controller.dpset')


class EventDPBase(event.EventBase):
    def __init__(self, dp):
        super(EventDPBase, self).__init__()
        self.dp = dp


class EventDP(EventDPBase):
    def __init__(self, dp, enter_leave):
        # enter_leave
        # True: dp entered
        # False: dp leaving
        super(EventDP, self).__init__(dp)
        self.enter_leave = enter_leave


class EventPortBase(EventDPBase):
    def __init__(self, dp, port):
        super(EventPortBase, self).__init__(dp)
        self.port = port


class EventPortAdd(EventPortBase):
    def __init__(self, dp, port):
        super(EventPortAdd, self).__init__(dp, port)


class EventPortDelete(EventPortBase):
    def __init__(self, dp, port):
        super(EventPortDelete, self).__init__(dp, port)


class EventPortModify(EventPortBase):
    def __init__(self, dp, new_port):
        super(EventPortModify, self).__init__(dp, new_port)


class PortState(dict):
    def __init__(self, dp):
        super(PortState, self).__init__()
        for port in dp.ports.values():
            self.add(port.port_no, port.state)

    def add(self, port_no, state):
        self[port_no] = state

    def remove(self, port_no):
        del self[port_no]

    def modify(self, port_no, state):
        self[port_no] = state


# this depends on controller::Datapath and dispatchers in handler
class DPSet(object):
    #def __init__(self):
    def __init__(self, ev_q, dispatcher_):
        super(DPSet, self).__init__()

        # dp registration and type setting can be occur in any order
        # Sometimes the sw_type is set before dp connection
        self.dp_types = {}

        self.dps = {}   # datapath_id => class Datapath
        self.port_state = {}  # datapath_id => ports
        self.ev_q = ev_q
        self.dispatcher = dispatcher_
        #self.ev_q = dispatcher.EventQueue(
        #        'datapath',
        #        dispatcher.EventDispatcher('dpset'))
        #self.dispatcher = dispatcher.EventDispatcher('dpset')

        handler.register_instance(self)

    def register(self, dp):
        assert dp.id is not None
        assert dp.id not in self.dps

        dp_type_ = self.dp_types.pop(dp.id, None)
        if dp_type_ is not None:
            dp.dp_type = dp_type_

        self.dps[dp.id] = dp
        self.port_state[dp.id] = PortState(dp)
        self.ev_q.queue(EventDP(dp, True))

    def unregister(self, dp):
        if dp.id in self.dps:
            self.ev_q.queue(EventDP(dp, False))
            del self.dps[dp.id]
            del self.port_state[dp.id]
            assert dp.id not in self.dp_types
            self.dp_types[dp.id] = getattr(dp, 'dp_type', dp_type.UNKNOWN)

    def set_type(self, dp_id, dp_type_=dp_type.UNKNOWN):
        if dp_id in self.dps:
            dp = self.dps[dp_id]
            dp.dp_type = dp_type_
        else:
            assert dp_id not in self.dp_types
            self.dp_types[dp_id] = dp_type_

    def get(self, dp_id):
        return self.dps.get(dp_id, None)

    def get_all(self):
        return self.dps.items()

    @set_ev_cls(dispatcher.EventDispatcherChange,
                dispatcher.QUEUE_EV_DISPATCHER)
    def dispacher_change(self, ev):
        LOG.debug('dispatcher change q %s dispatcher %s',
                  ev.ev_q.name, ev.new_dispatcher.name)
        if ev.ev_q.name != handler.QUEUE_NAME_OFP_MSG:
            return

        datapath = ev.ev_q.aux
        assert datapath is not None
        if ev.new_dispatcher.name == handler.DISPATCHER_NAME_OFP_MAIN:
            LOG.debug('DPSET: register datapath %s', datapath)
            self.register(datapath)
        elif ev.new_dispatcher.name == handler.DISPATCHER_NAME_OFP_DEAD:
            LOG.debug('DPSET: unregister datapath %s', datapath)
            self.unregister(datapath)

    @set_ev_cls(ofp_event.EventOFPPortStatus, handler.MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        datapath = msg.datapath
        port = msg.desc
        ofproto = datapath.ofproto

        LOG.debug('port status %s', reason)

        if reason == ofproto.OFPPR_ADD:
            self.port_state[datapath.id].add(port.port_no, port.state)
            self.ev_q.queue(EventPortAdd(datapath, port))
        elif reason == ofproto.OFPPR_DELETE:
            self.port_state[datapath.id].remove(port.port_no)
            self.ev_q.queue(EventPortDelete(datapath, port))
        else:
            assert reason == ofproto.OFPPR_MODIFY
            self.port_state[datapath.id].modify(port.port_no, port.state)
            self.ev_q.queue(EventPortModify(datapath, port))

    def get_port_state(self, dpid, port_no):
        try:
            return self.port_state[dpid][port_no]
        except KeyError:
            raise ryu_exc.PortNotFound(dpid=dpid, port=port_no,
                                       network_id=None)


DISPATCHER_NAME_DPSET = 'dpset'
DPSET_EV_DISPATCHER = dispatcher.EventDispatcher(DISPATCHER_NAME_DPSET)
QUEUE_NAME_DPSET = 'datapath'
_DPSET_EV_Q = dispatcher.EventQueue(QUEUE_NAME_DPSET, DPSET_EV_DISPATCHER)


def create_dpset():
    return DPSet(_DPSET_EV_Q, DPSET_EV_DISPATCHER)

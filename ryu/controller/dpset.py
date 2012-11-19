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


QUEUE_NAME_DPSET = 'dpset'
DISPATCHER_NAME_DPSET = 'dpset'
DPSET_EV_DISPATCHER = dispatcher.EventDispatcher(DISPATCHER_NAME_DPSET)


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
        self.ports = []  # port list when enter or leave


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
    def __init__(self):
        super(PortState, self).__init__()

    def add(self, port_no, port):
        self[port_no] = port

    def remove(self, port_no):
        del self[port_no]

    def modify(self, port_no, port):
        self[port_no] = port


# this depends on controller::Datapath and dispatchers in handler
class DPSet(object):
    def __init__(self):
        super(DPSet, self).__init__()

        # dp registration and type setting can be occur in any order
        # Sometimes the sw_type is set before dp connection
        self.dp_types = {}

        self.dps = {}   # datapath_id => class Datapath
        self.port_state = {}  # datapath_id => ports
        self.ev_q = dispatcher.EventQueueThread(QUEUE_NAME_DPSET,
                                                DPSET_EV_DISPATCHER)
        handler.register_instance(self)

    def register(self, dp):
        assert dp.id is not None
        assert dp.id not in self.dps

        dp_type_ = self.dp_types.pop(dp.id, None)
        if dp_type_ is not None:
            dp.dp_type = dp_type_

        self.dps[dp.id] = dp
        self.port_state[dp.id] = PortState()

        ev = EventDP(dp, True)
        for port in dp.ports.values():
            self._port_added(dp, port)
            ev.ports.append(port)
        self.ev_q.queue(ev)

    def unregister(self, dp):
        # Now datapath is already dead, so port status change event doesn't
        # interfere us.
        ev = EventDP(dp, False)
        for port in self.port_state.get(dp.id, {}).values():
            self._port_deleted(dp, port)
            ev.ports.append(port)
        self.ev_q.queue(ev)

        if dp.id in self.dps:
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
        return self.dps.get(dp_id)

    def get_all(self):
        return self.dps.items()

    def _port_added(self, datapath, port):
        self.port_state[datapath.id].add(port.port_no, port)

    def _port_deleted(self, datapath, port):
        self.port_state[datapath.id].remove(port.port_no)

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

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, handler.CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        datapath.ports = msg.ports

    @set_ev_cls(ofp_event.EventOFPPortStatus, handler.MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        datapath = msg.datapath
        port = msg.desc
        ofproto = datapath.ofproto

        LOG.debug('port status %s', reason)

        if reason == ofproto.OFPPR_ADD:
            self._port_added(datapath, port)
            self.ev_q.queue(EventPortAdd(datapath, port))
        elif reason == ofproto.OFPPR_DELETE:
            self._port_deleted(datapath, port)
            self.ev_q.queue(EventPortDelete(datapath, port))
        else:
            assert reason == ofproto.OFPPR_MODIFY
            self.port_state[datapath.id].modify(port.port_no, port)
            self.ev_q.queue(EventPortModify(datapath, port))

    def get_port(self, dpid, port_no):
        try:
            return self.port_state[dpid][port_no]
        except KeyError:
            raise ryu_exc.PortNotFound(dpid=dpid, port=port_no,
                                       network_id=None)

    def get_ports(self, dpid):
        return self.port_state[dpid].values()

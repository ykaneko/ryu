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

import collections
import logging

import ryu.exception as ryu_exc
from ryu.controller import event
from ryu.controller import dispatcher


LOG = logging.getLogger(__name__)


QUEUE_NAME_TUNNEL_EV = 'tunnel_event'
DISPATCHER_NAME_TUNNEL_EV = 'tunnel_event_handler'
TUNNEL_EV_DISPATCHER = dispatcher.EventDispatcher(DISPATCHER_NAME_TUNNEL_EV)


class EventTunnelKeyBase(event.EventBase):
    def __init__(self, network_id, tunnel_key):
        super(EventTunnelKeyBase, self).__init__()
        self.network_id = network_id
        self.tunnel_key = tunnel_key


class EventTunnelKeyAdd(EventTunnelKeyBase):
    def __init__(self, network_id, tunnel_key):
        super(EventTunnelKeyAdd, self).__init__(network_id, tunnel_key)


class EventTunnelKeyDel(EventTunnelKeyBase):
    def __init__(self, network_id, tunnel_key):
        super(EventTunnelKeyDel, self).__init__(network_id, tunnel_key)


class EventTunnelPort(event.EventBase):
    def __init__(self, dpid, port_no, remote_dpid, add_del):
        super(EventTunnelPort, self).__init__()
        self.dpid = dpid
        self.port_no = port_no
        self.remote_dpid = remote_dpid
        self.add_del = add_del


class TunnelKeys(dict):
    """network id(uuid) <-> tunnel key(32bit unsigned int)"""
    def __init__(self, ev_q):
        super(TunnelKeys, self).__init__()
        self.ev_q = ev_q

    def get_key(self, network_id):
        try:
            return self[network_id]
        except KeyError:
            raise ryu_exc.TunnelKeyNotFound(network_id=network_id)

    def _set_key(self, network_id, tunnel_key):
        self[network_id] = tunnel_key
        self.ev_q.queue(EventTunnelKeyAdd(network_id, tunnel_key))

    def register_key(self, network_id, tunnel_key):
        if network_id in self:
            raise ryu_exc.NetworkAlreadyExist(network_id=network_id)
        if tunnel_key in self.values():
            raise ryu_exc.TunnelKeyAlreadyExist(tunnel_key=tunnel_key)
        self._set_key(network_id, tunnel_key)

    def update_key(self, network_id, tunnel_key):
        if network_id not in self and tunnel_key in self.values():
            raise ryu_exc.TunnelKeyAlreadyExist(key=tunnel_key)

        key = self.get(network_id)
        if key is None:
            self._set_key(network_id, tunnel_key)
            return
        if key != tunnel_key:
            raise ryu_exc.NetworkAlreadyExist(network_id=network_id)

    def delete_key(self, network_id):
        try:
            tunnel_key = self[network_id]
            self.ev_q.queue(EventTunnelKeyDel(network_id, tunnel_key))
            del self[network_id]
        except KeyError:
            raise ryu_exc.NetworkNotFound(network_id=network_id)


class DPIDs(object):
    """dpid -> port_no -> remote_dpid"""
    def __init__(self, ev_q):
        super(DPIDs, self).__init__()
        self.dpids = collections.defaultdict(dict)
        self.ev_q = ev_q

    def list_ports(self, dpid):
        return self.dpids[dpid]

    def _add_remote_dpid(self, dpid, port_no, remote_dpid):
        self.dpids[dpid][port_no] = remote_dpid
        self.ev_q.queue(EventTunnelPort(dpid, port_no, remote_dpid, True))

    def add_remote_dpid(self, dpid, port_no, remote_dpid):
        if port_no in self.dpids[dpid]:
            raise ryu_exc.PortAlreadyExist(dpid=dpid, port=port_no,
                                           network_id=None)
        self._add_remote_dpid(dpid, port_no, remote_dpid)

    def update_remote_dpid(self, dpid, port_no, remote_dpid):
        remote_dpid_ = self.dpids[dpid].get(port_no)
        if remote_dpid_ is None:
            self._add_remote_dpid(dpid, port_no, remote_dpid)
        elif remote_dpid_ != remote_dpid:
            raise ryu_exc.RemoteDPIDAlreadyExist(dpid=dpid, port=port_no,
                                                 remote_dpid=remote_dpid)

    def get_remote_dpid(self, dpid, port_no):
        try:
            return self.dpids[dpid][port_no]
        except KeyError:
            raise ryu_exc.PortNotFound(dpid=dpid, port=port_no)

    def delete_port(self, dpid, port_no):
        try:
            remote_dpid = self.dpids[dpid][port_no]
            self.ev_q.queue(EventTunnelPort(dpid, port_no, remote_dpid, False))
            del self.dpids[dpid][port_no]
        except KeyError:
            raise ryu_exc.PortNotFound(dpid=dpid, port=port_no)

    def get_port(self, dpid, remote_dpid):
        try:
            dp = self.dpids[dpid]
        except KeyError:
            raise ryu_exc.PortNotFound(dpid=dpid, port=None, network_id=None)

        res = [port_no for (port_no, remote_dpid_) in dp.items()
               if remote_dpid_ == remote_dpid]
        assert len(res) <= 1
        if len(res) == 0:
            raise ryu_exc.PortNotFound(dpid=dpid, port=None, network_id=None)
        return res[0]


class Tunnels(object):
    def __init__(self):
        super(Tunnels, self).__init__()
        ev_q = dispatcher.EventQueue(QUEUE_NAME_TUNNEL_EV,
                                     TUNNEL_EV_DISPATCHER)
        self.tunnel_keys = TunnelKeys(ev_q)
        self.dpids = DPIDs(ev_q)

    def get_key(self, network_id):
        return self.tunnel_keys.get_key(network_id)

    def register_key(self, network_id, tunnel_key):
        self.tunnel_keys.register_key(network_id, tunnel_key)

    def update_key(self, network_id, tunnel_key):
        self.tunnel_keys.update_key(network_id, tunnel_key)

    def delete_key(self, network_id):
        self.tunnel_keys.delete_key(network_id)

    def list_ports(self, dpid):
        return self.dpids.list_ports(dpid).keys()

    def register_port(self, dpid, port_no, remote_dpid):
        self.dpids.add_remote_dpid(dpid, port_no, remote_dpid)

    def update_port(self, dpid, port_no, remote_dpid):
        self.dpids.update_remote_dpid(dpid, port_no, remote_dpid)

    def get_remote_dpid(self, dpid, port_no):
        return self.dpids.get_remote_dpid(dpid, port_no)

    def delete_port(self, dpid, port_no):
        self.dpids.delete_port(dpid, port_no)

    #
    # methods for gre tunnel
    #
    def get_port(self, dpid, remote_dpid):
        return self.dpids.get_port(dpid, remote_dpid)

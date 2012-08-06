# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
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

import sys
import gflags
import logging

from gevent.server import StreamServer
from gevent import monkey
monkey.patch_all()

from sqlalchemy import or_
from sqlalchemy.exc import OperationalError, NoSuchTableError
from sqlalchemy.orm import exc
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.ext.sqlsoup import SqlSoup

from ovs import json
from ovs.jsonrpc import Message

from quantumclient.v2_0 import client as q_client

from ryu.app import client as ryu_client
from ryu.app import rest_nw_id
from ryu.base import app_manager


LOG = logging.getLogger('quantum_adapter')

FLAGS = gflags.FLAGS
gflags.DEFINE_string('rpc_listen_host', '127.0.0.1',
                     'quantum adapter listen host')
gflags.DEFINE_integer('rpc_listen_port', 6634,
                      'quantum adapter listen port')
gflags.DEFINE_string(
    'sql_connection',
    'mysql://root:mysql@192.168.122.10/ovs_quantum?charset=utf8',
    'database connection')
gflags.DEFINE_string('int_bridge', 'br-int', 'integration bridge name')
gflags.DEFINE_string('quantum_url', 'http://192.168.122.10:9696',
                     'URL for connecting to quantum')
gflags.DEFINE_integer('quantum_url_timeout', 30,
                      'timeout value for connecting to quantum in seconds')
gflags.DEFINE_string('quantum_admin_username', 'quantum',
                     'username for connecting to quantum in admin context')
gflags.DEFINE_string('quantum_admin_password', 'service_password',
                     'password for connecting to quantum in admin context')
gflags.DEFINE_string('quantum_admin_tenant_name', '',
                     'tenant name for connecting to quantum in admin context')
gflags.DEFINE_string('quantum_admin_auth_url', 'http://localhost:5000/v2.0',
                     'auth url for connecting to quantum in admin context')
gflags.DEFINE_string(
    'quantum_auth_strategy',
    'keystone',
    'auth strategy for connecting to quantum in admin context')


def _get_quantum_client():
    return q_client.Client(endpoint_url=FLAGS.quantum_url,
                           auth_strategy=None,
                           timeout=FLAGS.quantum_url_timeout)


PORT_UNKNOWN = 0
PORT_GATEWAY = 1
PORT_GUEST = 2
PORT_TUNNEL = 3


class OVSPort(object):
    # extra-ids: 'attached-mac', 'iface-id', 'iface-status', 'vm-uuid'

    def __init__(self, row, port):
        super(OVSPort, self).__init__()
        self.row = row
        self.link_state = None
        self.name = None
        self.ofport = None
        self.type = None
        self.ext_ids = {}
        self.options = {}
        self.update(port)

    def update(self, port):
        for key in ['link_state', 'name', 'ofport', 'type']:
            if key in port:
                self.__dict__[key] = port[key]
        if 'external_ids' in port:
            self.ext_ids = dict((name, val)
                                for (name, val) in port['external_ids'][1])
        if 'options' in port:
            self.options = dict((name, val)
                                for (name, val) in port['options'][1])

    def get_port_type(self):
        if not isinstance(self.ofport, int):
            return PORT_UNKNOWN
        if self.type == 'internal' and 'iface-id' in self.ext_ids:
            return PORT_GATEWAY
        if (self.type == 'gre' and 'local_ip' in self.options and
                'remote_ip' in self.options):
            return PORT_TUNNEL
        if self.type == '' and 'vm-uuid' in self.ext_ids:
            return PORT_GUEST
        return PORT_UNKNOWN

    def __str__(self):
        return "name=%s type=%s ofport=%s state=%s ext_ids=%s options=%s" % (
            self.name, self.type, self.ofport, self.link_state,
            self.ext_ids, self.options)


S_DPID_GET = 0      # start datapath-id monitoring
S_PORT_GET = 1      # start port monitoring
S_MONITOR = 2      # datapath-id/port monitoring


class OVSMonitor(object):
    def __init__(self, sock, addr, db, q_client, ryu_rest_client,
                 gre_tunnel_client):
        super(OVSMonitor, self).__init__()
        self.socket = sock
        self.address = addr
        self.tunnel_ip, port_ = addr
        self.db = db
        self.q_client = q_client
        self.api = ryu_rest_client
        self.tunnel_api = gre_tunnel_client

        self.state = None
        self.parser = None
        self.dpid = None
        self.is_active = True

        self.handlers = {}
        self.handlers[S_DPID_GET] = {Message.T_REPLY: self.receive_dpid}
        self.handlers[S_PORT_GET] = {Message.T_REPLY: self.receive_port}
        self.handlers[S_MONITOR] = {Message.T_NOTIFY: {
            'dpid_monitor': self.monitor_dpid,
            'port_monitor': self.monitor_port
        }}

    def notify_quantum(self, port):
        LOG.debug("notify: %s", port)
        try:
            port_info = self.db.ports.filter(
                self.db.ports.id == port.ext_ids['iface-id']).one()
        except exc.NoResultFound:
            LOG.warn("port not found: %s", port.ext_ids['iface-id'])
            self.db.commit()
            return
        except (NoSuchTableError, OperationalError):
            LOG.warn("could not access database")
            self.db.rollback()
            return

        port_data = {
            'state': 'ACTIVE',
            'datapath_id': self.dpid,
            'port_no': port.ofport,
        }
        body = {'port': port_data}
        LOG.debug("port-body = %s", body)
        try:
            self.q_client.update_port(port_info.id, body)
        except Exception as e:
            LOG.debug("quantum_client.update_port failed: %s", e)
            pass
        self.db.commit()

    def update_gre_port(self, port):
        LOG.debug("update_gre_port: %s", port)
        try:
            node = self.db.ovs_node.filter(
                self.db.ovs_node.address == port.options['remote_ip']).one()
        except exc.NoResultFound:
            LOG.debug("gre port not found: %s", port)
            #self._del_port(port.name, port.ofport)
            pass
        else:
            LOG.debug("update gre port: %s", port)
            self.api.update_port(rest_nw_id.NW_ID_VPORT_GRE,
                                 self.dpid, port.ofport)
            self.tunnel_api.update_remote_dpid(self.dpid, port.ofport,
                                               node.dpid)

    def update_port(self, data):
        for row in data:
            table = data[row]
            new_port = None
            old_port = None
            if "new" in table:
                new_port = OVSPort(row, table['new'])
            if "old" in table:
                old_port = OVSPort(row, table['old'])

            if old_port == new_port:
                continue
            if not new_port:
                if old_port.get_port_type() != PORT_UNKNOWN:
                    LOG.info("delete port: %s", old_port)
                continue
            if not old_port:
                if new_port.get_port_type() != PORT_UNKNOWN:
                    LOG.info("create port: %s", new_port)
                    if new_port.get_port_type() != PORT_TUNNEL:
                        self.notify_quantum(new_port)
                    else:
                        self.update_gre_port(new_port)
                continue
            if (new_port.get_port_type() == PORT_GUEST or
                    new_port.get_port_type() == PORT_GATEWAY):
                LOG.info("update port: %s", new_port)
                self.notify_quantum(new_port)

    def update_ovs_node(self):
        dpid_or_ip = or_(self.db.ovs_node.dpid == self.dpid,
                         self.db.ovs_node.address == self.tunnel_ip)
        try:
            nodes = self.db.ovs_node.filter(dpid_or_ip).all()
        except exc.NoResultFound:
            pass
        else:
            for node in nodes:
                LOG.debug("node %s", node)
                if node.dpid == self.dpid and node.address == self.tunnel_ip:
                    pass
                elif node.dpid == self.dpid:
                    LOG.warn("updating node %s %s -> %s",
                             node.dpid, node.address, self.tunnel_ip)
                else:
                    LOG.warn("deleting node %s", node)
                self.db.delete(node)
        self.db.ovs_node.insert(dpid=self.dpid, address=self.tunnel_ip)
        self.db.commit()

    def update_dpid(self, data):
        old_dpid = self.dpid
        for row in data:
            table = data[row]
            if "new" in table:
                name = table['new']['name']
                dpid = table['new']['datapath_id']
                if name == FLAGS.int_bridge and isinstance(dpid, basestring):
                    LOG.debug("datapath_id = %s", dpid)
                    self.dpid = dpid
                    break

    def monitor_port(self, msg):
        key, args = msg.params
        if not "Interface" in args:
            return
        data = args['Interface']
        self.update_port(data)

    def monitor_dpid(self, msg):
        key, args = msg.params
        if not "Bridge" in args:
            return
        data = args['Bridge']
        self.update_dpid(data)

    def receive_port(self, msg):
        if not "Interface" in msg.result:
            return
        data = msg.result['Interface']
        self.update_port(data)
        self.state = S_MONITOR

    def start_port_monitor(self):
        self.state = S_PORT_GET
        params = json.from_string(
            '["Open_vSwitch", "port_monitor", \
                {"Interface": [{"columns": \
                    ["name", "ofport", "type", "link_state",\
                    "external_ids", "options"]}]}]')
        self.send_request("monitor", params)

    def receive_dpid(self, msg):
        if not "Bridge" in msg.result:
            return
        data = msg.result['Bridge']
        self.update_dpid(data)
        self.update_ovs_node()
        self.start_port_monitor()

    def start_dpid_monitor(self):
        self.state = S_DPID_GET
        params = json.from_string(
            '["Open_vSwitch", "dpid_monitor", \
                {"Bridge": {"columns": ["datapath_id", "name"]}}]')
        self.send_request("monitor", params)

    def shutdown(self):
        LOG.info("shutdown: %s: dpid=%s", self.address, self.dpid)
        self.is_active = False

    def handle_rpc(self, msg):
        handler = None
        try:
            handler = self.handlers[self.state][msg.type]
        except KeyError:
            pass

        if msg.type == Message.T_REQUEST:
            if msg.method == "echo":
                reply = Message.create_reply(msg.params, msg.id)
                self.send(reply)
            elif handler:
                handler(msg)
            else:
                reply = Message.create_error({"error": "unknown method"},
                                             msg.id)
                self.send(reply)
                LOG.warn("unknown request: %s", msg)
        elif msg.type == Message.T_REPLY:
            if handler:
                handler(msg)
            else:
                LOG.warn("unknown reply: %s", msg)
        elif msg.type == Message.T_NOTIFY:
            if msg.method == "shutdown":
                self.shutdown()
            elif handler:
                if msg.method == "update":
                    key, args = msg.params
                    if key in handler:
                        handler[key](msg)
            else:
                LOG.warn("unknown notification: %s", msg)
        else:
            LOG.warn("unsolicited JSON-RPC reply or error: %s", msg)

        return

    def process_msg(self):
        json = self.parser.finish()
        self.parser = None
        if isinstance(json, basestring):
            LOG.warn("error parsing stream: %s", json)
            return
        msg = Message.from_json(json)
        if not isinstance(msg, Message):
            LOG.warn("received bad JSON-RPC message: %s", msg)
            return
        return msg

    def recv_loop(self):
        while self.is_active:
            buf = ""
            ret = self.socket.recv(4096)
            if len(ret) == 0:
                self.is_active = False
                return
            buf += ret
            while buf:
                if self.parser is None:
                    self.parser = json.Parser()
                buf = buf[self.parser.feed(buf):]
                if self.parser.is_done():
                    msg = self.process_msg()
                    if msg:
                        self.handle_rpc(msg)

    def send(self, msg):
        if msg.is_valid():
            LOG.warn("not a valid JSON-RPC request: %s", msg)
            return
        buf = json.to_string(msg.to_json())
        self.socket.sendall(buf)

    def send_request(self, method, params):
        msg = Message.create_request(method, params)
        self.send(msg)

    def close(self):
        self.socket.close()

    def serve(self):
        LOG.info("connect: %s", self.address)
        self.api.update_network(rest_nw_id.NW_ID_VPORT_GRE)
        self.start_dpid_monitor()
        self.recv_loop()
        self.close()


def check_ofp_mode(db):
    LOG.debug("checking db")

    servers = db.ofp_server.all()

    ofp_contoroller_addr = None
    ofp_rest_api_addr = None
    for serv in servers:
        if serv.host_type == "REST_API":
            ofp_rest_api_addr = serv.address
        elif serv.host_type == "controller":
            ofp_controller_addr = serv.address
        else:
            LOG.warn("ignoring unknown server type %s", serv)

    LOG.debug("controller %s", ofp_controller_addr)
    LOG.debug("api %s", ofp_rest_api_addr)
    if not ofp_controller_addr:
        raise RuntimeError("OF controller isn't specified")
    if not ofp_rest_api_addr:
        raise RuntimeError("Ryu rest API port isn't specified")

    LOG.debug("going to ofp controller mode %s %s",
              ofp_controller_addr, ofp_rest_api_addr)
    return (ofp_controller_addr, ofp_rest_api_addr)


class QuantumAdapter(app_manager.RyuApp):
    def __init__(self, *_args, **kwargs):
        super(QuantumAdapter, self).__init__()
        server = StreamServer((FLAGS.rpc_listen_host, FLAGS.rpc_listen_port),
                              QuantumAdapter.connection)
        server.serve_forever()

    @staticmethod
    def connection(sock, addr):
        q_client = _get_quantum_client()
        db = SqlSoup(FLAGS.sql_connection,
                     session=scoped_session(
                         sessionmaker(autoflush=True,
                                      expire_on_commit=False,
                                      autocommit=True)))
        ofp_ctrl_addr_, ofp_rest_api_addr = check_ofp_mode(db)
        ryu_rest_client = ryu_client.OFPClient(ofp_rest_api_addr)
        gt_client = ryu_client.GRETunnelClient(ofp_rest_api_addr)
        mon = OVSMonitor(sock, addr, db, q_client, ryu_rest_client, gt_client)
        mon.serve()


def main():
    log = logging.getLogger()
    log.addHandler(logging.StreamHandler(sys.stderr))
    log.setLevel(logging.DEBUG)
    adapter = QuantumAdapter()


if __name__ == '__main__':
    main()

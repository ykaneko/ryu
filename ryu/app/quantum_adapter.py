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

import gflags
import logging
import socket
import ssl
import sys
import uuid

from gevent import monkey
import gevent
monkey.patch_all()

from sqlalchemy import or_
from sqlalchemy.exc import NoSuchTableError, OperationalError
from sqlalchemy.ext.sqlsoup import SqlSoup
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm.exc import NoResultFound

from ovs import json
from ovs.jsonrpc import Message

from quantumclient import client as q_client
from quantumclient.common import exceptions as q_exc
from quantumclient.v2_0 import client as q_clientv2

from ryu.app import client as ryu_client
from ryu.app import conf_switch_key as cs_key
from ryu.app import rest_nw_id
from ryu.base import app_manager
from ryu.controller import conf_switch, handler


LOG = logging.getLogger('quantum_adapter')

FLAGS = gflags.FLAGS
gflags.DEFINE_string(
    'sql_connection',
    'mysql://root:mysql@192.168.122.10/ovs_quantum?charset=utf8',
    'database connection')
gflags.DEFINE_string('int_bridge', 'br-int', 'integration bridge name')

gflags.DEFINE_string('quantum_url', 'http://localhost:9696',
                     'URL for connecting to quantum')
gflags.DEFINE_integer('quantum_url_timeout', 30,
                      'timeout value for connecting to quantum in seconds')
gflags.DEFINE_string('quantum_admin_username', 'quantum',
                     'username for connecting to quantum in admin context')
gflags.DEFINE_string('quantum_admin_password', 'service_password',
                     'password for connecting to quantum in admin context')
gflags.DEFINE_string('quantum_admin_tenant_name', 'service',
                     'tenant name for connecting to quantum in admin context')
gflags.DEFINE_string('quantum_admin_auth_url', 'http://localhost:5000/v2.0',
                     'auth url for connecting to quantum in admin context')
gflags.DEFINE_string(
    'quantum_auth_strategy',
    'keystone',
    'auth strategy for connecting to quantum in admin context')


def _get_auth_token():
    httpclient = q_client.HTTPClient(
        username=FLAGS.quantum_admin_username,
        tenant_name=FLAGS.quantum_admin_tenant_name,
        password=FLAGS.quantum_admin_password,
        auth_url=FLAGS.quantum_admin_auth_url,
        timeout=FLAGS.quantum_url_timeout,
        auth_strategy=FLAGS.quantum_auth_strategy)
    try:
        httpclient.authenticate()
    except (q_exc.Unauthorized, q_exc.Forbidden, q_exc.EndpointNotFound) as e:
        LOG.error("authentication failure: %s", e)
        return None
    LOG.debug("_get_auth_token: token=%s", httpclient.auth_token)
    return httpclient.auth_token


def _get_quantum_client(token):
    if token:
        my_client = q_clientv2.Client(
            endpoint_url=FLAGS.quantum_url,
            token=token, timeout=FLAGS.quantum_url_timeout)
    else:
        my_client = q_clientv2.Client(
            endpoint_url=FLAGS.quantum_url,
            auth_strategy=None, timeout=FLAGS.quantum_url_timeout)
    return my_client


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
S_CTRL_SET = 1      # start set controller
S_PORT_GET = 2      # start port monitoring
S_MONITOR = 3       # datapath-id/port monitoring


class OVSMonitor(object):
    def __init__(self, dpid, db, q_api, ryu_rest_client, gre_tunnel_client,
                 ctrl_addr):
        super(OVSMonitor, self).__init__()
        self.dpid = dpid
        self.db = db
        self.q_api = q_api
        self.api = ryu_rest_client
        self.tunnel_api = gre_tunnel_client
        self.ctrl_addr = ctrl_addr

        self.address = None
        self.tunnel_ip = None
        self.int_bridge = None
        self.socket = None
        self.state = None
        self.parser = None
        self.dpid_row = None
        self.is_active = False

        self.handlers = {}
        self.handlers[S_DPID_GET] = {Message.T_REPLY: self.receive_dpid}
        self.handlers[S_CTRL_SET] = {Message.T_REPLY:
                                     self.receive_set_controller}
        self.handlers[S_PORT_GET] = {Message.T_REPLY: self.receive_port}
        self.handlers[S_MONITOR] = {Message.T_NOTIFY: {
            'port_monitor': self.monitor_port
        }}

    def update_vif_port(self, port, delete=False):
        LOG.debug("update_vif_port: %s", port)
        try:
            port_info = self.db.ports.filter(
                self.db.ports.id == port.ext_ids['iface-id']).one()
        except NoResultFound:
            LOG.warn("port not found: %s", port.ext_ids['iface-id'])
            self.db.commit()
            return
        except (NoSuchTableError, OperationalError):
            LOG.error("could not access database")
            self.db.rollback()
            # TODO: If OperationalError occurred, it should re-connect to
            # the database (re-create SplSoup object)
            return

        if port.link_state == 'up':
            state = True
        else:
            state = False
        port_data = {
            'admin_state_up': state,
            'datapath_id': self.dpid,
            'port_no': port.ofport,
        }
        body = {'port': port_data}
        LOG.debug("port-body = %s", body)
        try:
            if not delete:
                self.q_api.update_port(port_info.id, body)
            else:
                self.q_api.delete_port(port_info.id)
        except (q_exc.ConnectionFailed, q_exc.QuantumClientException) as e:
            LOG.error("quantum update port failed: %s", e)
            # TODO: When authentication failure occurred, it should get auth
            # token again
        self.db.commit()

    def update_gre_port(self, port):
        LOG.debug("update_gre_port: %s", port)
        try:
            node = self.db.ovs_node.filter(
                self.db.ovs_node.address == port.options['remote_ip']).one()
        except NoResultFound:
            LOG.debug("gre port not found: %s", port)
        else:
            LOG.debug("update gre port: %s", port)
            self.api.update_port(rest_nw_id.NW_ID_VPORT_GRE,
                                 self.dpid, port.ofport)
            self.tunnel_api.update_remote_dpid(self.dpid, port.ofport,
                                               node.dpid)
        self.db.commit()

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
                    if old_port.get_port_type() != PORT_TUNNEL:
                        self.update_vif_port(old_port, delete=True)
                continue
            if not old_port:
                if new_port.get_port_type() != PORT_UNKNOWN:
                    LOG.info("create port: %s", new_port)
                    if new_port.get_port_type() != PORT_TUNNEL:
                        self.update_vif_port(new_port)
                    else:
                        self.update_gre_port(new_port)
                continue
            if (new_port.get_port_type() == PORT_GUEST or
                    new_port.get_port_type() == PORT_GATEWAY):
                LOG.info("update port: %s", new_port)
                self.update_vif_port(new_port)

    def update_dpid(self, data):
        for row in data:
            table = data[row]
            if "new" in table:
                int_bridge = table['new']['name']
                dpid = table['new']['datapath_id']
                if dpid == self.dpid:
                    LOG.debug("datapath_id=%s name=%s", dpid, int_bridge)
                    self.dpid_row = row
                    self.int_bridge = int_bridge
                    break

    def monitor_port(self, msg):
        _key, args = msg.params
        if not "Interface" in args:
            return
        data = args['Interface']
        self.update_port(data)

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

    def receive_set_controller(self, msg):
        LOG.debug("set controller: %s", msg)
        for row in msg.result:
            if "error" in row:
                err = str(row["error"])
                if "details" in row:
                    err += ": " + str(row["details"])
                LOG.error("could not set controller: %s", err)
                self.is_active = False
                return
        self.start_port_monitor()

    def start_set_controller(self):
        self.state = S_CTRL_SET
        uuid_ = str(uuid.uuid4()).replace('-', '_')
        params = json.from_string(
            '["Open_vSwitch", \
             {"op": "insert", "table": "Controller", \
              "row": {"target": "tcp:%s"}, "uuid-name": "row%s"},\
             {"op": "update", "table": "Bridge", \
              "row": {"controller": ["named-uuid","row%s"]}, \
              "where": [["_uuid","==",["uuid","%s"]]]}]' %
            (str(self.ctrl_addr), uuid_, uuid_, str(self.dpid_row)))
        self.send_request("transact", params)

    def receive_dpid(self, msg):
        if not "Bridge" in msg.result:
            return
        data = msg.result['Bridge']
        self.update_dpid(data)
        self.start_set_controller()

    def start_dpid_monitor(self):
        self.state = S_DPID_GET
        params = json.from_string(
            '["Open_vSwitch", "dpid_monitor", \
                {"Bridge": {"columns": ["datapath_id", "name"]}}]')
        self.send_request("monitor", params)

    def handle_rpc(self, msg):
        _handler = None
        try:
            _handler = self.handlers[self.state][msg.type]
        except KeyError:
            pass

        if msg.type == Message.T_REQUEST:
            if msg.method == "echo":
                reply = Message.create_reply(msg.params, msg.id)
                self.send(reply)
            elif _handler:
                _handler(msg)
            else:
                reply = Message.create_error({"error": "unknown method"},
                                             msg.id)
                self.send(reply)
                LOG.warn("unknown request: %s", msg)
        elif msg.type == Message.T_REPLY:
            if _handler:
                _handler(msg)
            else:
                LOG.warn("unknown reply: %s", msg)
        elif msg.type == Message.T_NOTIFY:
            if msg.method == "shutdown":
                self.shutdown()
            elif _handler:
                if msg.method == "update":
                    key, _args = msg.params
                    if key in _handler:
                        _handler[key](msg)
            else:
                LOG.warn("unknown notification: %s", msg)
        else:
            LOG.warn("unsolicited JSON-RPC reply or error: %s", msg)

        self.db.commit()
        return

    def process_msg(self):
        _json = self.parser.finish()
        self.parser = None
        if isinstance(_json, basestring):
            LOG.warn("error parsing stream: %s", _json)
            return
        msg = Message.from_json(_json)
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

    def set_ovsdb_addr(self, address):
        _proto, _host, _port = address.split(':')
        self.address = address

    def shutdown(self):
        LOG.info("shutdown: %s: dpid=%s", self.address, self.dpid)
        self.is_active = False

    def serve(self):
        if not self.address:
            return
        self.api.update_network(rest_nw_id.NW_ID_VPORT_GRE)

        proto, host, port = self.address.split(':')
        if proto not in ['tcp', 'ssl']:
            proto = 'tcp'
        if self.socket:
            self.close()
        self.socket = gevent.socket.socket()
        if proto == 'ssl':
            self.socket = gevent.ssl.wrap_socket(self.socket)
        try:
            self.socket.connect((host, int(port)))
        except (socket.error, socket.timeout) as e:
            LOG.error("TCP connection failure: %s", e)
            raise e
        except ssl.SSLError as e:
            LOG.error("SSL connection failure: %s", e)
            raise e
        LOG.info("connect: %s", self.address)
        self.is_active = True

        self.start_dpid_monitor()
        self.recv_loop()
        self.close()


def check_ofp_mode(db):
    LOG.debug("checking db")

    servers = db.ofp_server.all()

    ofp_controller_addr = None
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


def create_monitor(dpid):
    db = SqlSoup(FLAGS.sql_connection,
                 session=scoped_session(sessionmaker(autoflush=True,
                                                     expire_on_commit=False,
                                                     autocommit=False)))
    token = None
    if FLAGS.quantum_auth_strategy:
        token = _get_auth_token()
    q_api = _get_quantum_client(token)

    ofp_ctrl_addr, ofp_rest_api_addr = check_ofp_mode(db)
    ryu_rest_client = ryu_client.OFPClient(ofp_rest_api_addr)
    gt_client = ryu_client.TunnelClient(ofp_rest_api_addr)

    return OVSMonitor(dpid, db, q_api, ryu_rest_client, gt_client,
                      ofp_ctrl_addr)


class QuantumAdapter(app_manager.RyuApp):
    _CONTEXTS = {
        'conf_switch': conf_switch.ConfSwitchSet
    }

    def __init__(self, *_args, **kwargs):
        super(QuantumAdapter, self).__init__()
        self.cs = kwargs['conf_switch']
        self.db = SqlSoup(FLAGS.sql_connection,
                          session=scoped_session(
                              sessionmaker(autoflush=True,
                                           expire_on_commit=False,
                                           autocommit=False)))
        self.monitors = {}

    @staticmethod
    def update_ovs_node(db, dpid, tunnel_ip):
        dpid_or_ip = or_(db.ovs_node.dpid == dpid,
                         db.ovs_node.address == tunnel_ip)
        try:
            nodes = db.ovs_node.filter(dpid_or_ip).all()
        except NoResultFound:
            pass
        else:
            for node in nodes:
                LOG.debug("node %s", node)
                if node.dpid == dpid and node.address == tunnel_ip:
                    pass
                elif node.dpid == dpid:
                    LOG.warn("updating node %s %s -> %s",
                             node.dpid, node.address, tunnel_ip)
                else:
                    LOG.warn("deleting node %s", node)
                db.delete(node)
        db.ovs_node.insert(dpid=dpid, address=tunnel_ip)
        db.commit()

    @staticmethod
    def delete_ovs_node(db, dpid):
        try:
            node = db.ovs_node.filter(db.ovs_node.dpid == dpid).one()
        except NoResultFound:
            pass
        else:
            db.delete(node)
        db.commit()

    @handler.set_ev_cls(conf_switch.EventConfSwitchSet,
                        conf_switch.CONF_SWITCH_EV_DISPATCHER)
    def conf_switch_set_handler(self, ev):
        LOG.debug("conf_switch set: %s", ev)
        dpid = ev.dpid
        if ev.key == cs_key.OVSDB_ADDR:
            if dpid in self.monitors:
                mon = self.monitors[dpid]
                mon.shutdown()
            mon = create_monitor(dpid)
            mon.set_ovsdb_addr(ev.value)
            mon.serve()
            self.monitors[dpid] = mon
        elif ev.key == cs_key.OVS_TUNNEL_ADDR:
            self.update_ovs_node(self.db, dpid, ev.value)
        else:
            LOG.debug("unknown event: %s", ev)

    @handler.set_ev_cls(conf_switch.EventConfSwitchDel,
                        conf_switch.CONF_SWITCH_EV_DISPATCHER)
    def conf_switch_del_handler(self, ev):
        LOG.debug("conf_switch del: %s", ev)
        dpid = ev.dpid
        if ev.key == cs_key.OVSDB_ADDR:
            if dpid not in self.monitors:
                LOG.error("no monitor found: %s", ev)
                return
            mon = self.monitors[dpid]
            mon.shutdown()
            del(self.monitors[dpid])
        elif ev.key == cs_key.OVS_TUNNEL_ADDR:
            self.delete_ovs_node(self.db, dpid)
        else:
            LOG.debug("unknown event: %s", ev)

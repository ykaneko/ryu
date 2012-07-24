# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2012 Isaku Yamahata <yamahata at private email ne jp>
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

import json
from webob import Request, Response

from ryu.base import app_manager
from ryu.app.wsgi import ControllerBase, WSGIApplication

import ryu.exception as ryu_exc
from ryu.controller import network
from ryu.controller import tunnels


# REST API for tunneling
#
# register GRE tunnel key of this network
# Fail if the key is already registered
# POST /v1.0/tunnels/gre/networks/{network-id}/key/{tunnel_key}
#
# register GRE tunnel key of this network
# Success as nop even if the same key is already registered
# PUT /v1.0/tunnels/gre/networks/{network-id}/key/{tunnel_key}
#
# return allocated GRE tunnel key of this network
# GET /v1.0/tunnels/gre/networks/{network-id}/key
#
# get the ports of dpid that are used for tunneling
# GET /v1.0/tunnels/gre/switches/{dpid}/ports
#
# get the dpid of the other end of tunnel
# GET /v1.0/tunnels/gre/switches/{dpid}/ports/{port-id}/
#
# register the dpid of the other end of tunnel
# Fail if the dpid is already registered
# POST /v1.0/tunnels/gre/switches/{dpid}/ports/{port-id}/{remote_dpip}
#
# register the dpid of the other end of tunnel
# Success as nop even if the dpid is already registered
# PUT /v1.0/tunnels/gre/switches/{dpid}/ports/{port-id}/{remote_dpip}


class TunnelKeyController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(TunnelKeyController, self).__init__(req, link, data, **config)
        self.tunnels = data

    def create(self, req, network_id, tunnel_key, **_kwargs):
        try:
            self.tunnels.register_key(network_id, int(tunnel_key))
        except (ryu_exc.NetworkAlreadyExist, ryu_exc.TunnelKeyAlreadyExist):
            return Response(status=409)

        return Response(status=200)

    def update(self, req, network_id, tunnel_key, **_kwargs):
        try:
            self.tunnels.update_key(network_id, int(tunnel_key))
        except (ryu_exc.NetworkAlreadyExist, ryu_exc.TunnelKeyAlreadyExist):
            return Response(status=409)

        return Response(status=200)

    def lists(self, req, network_id, **_kwargs):
        try:
            tunnel_key = self.tunnels.get_key(network_id)
        except ryu_exc.TunnelKeyNotFound:
            return Response(status=404)
        body = json.dumps(tunnel_key)

        return Response(content_type='application/json', body=body)

    def delete(self, req, network_id, **_kwargs):
        try:
            self.tunnels.delete_key(network_id)
        except (ryu_exc.NetworkNotFound, ryu_exc.TunnelKeyNotFound):
            return Response(status=404)

        return Response(status=200)


class TunnelPortController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(TunnelPortController, self).__init__(req, link, data, **config)
        self.tunnels = data

    def create(self, req, dpid, port_id, remote_dpid, **_kwargs):
        try:
            self.tunnels.register_port(int(dpid, 16), int(port_id),
                                       int(remote_dpid, 16))
        except ryu_exc.PortAlreadyExist:
            return Response(status=409)

        return Response(status=200)

    def update(self, req, dpid, port_id, remote_dpid, **_kwargs):
        try:
            self.tunnels.update_port(int(dpid, 16), int(port_id),
                                     int(remote_dpid, 16))
        except ryu_exc.RemoteDPIDAlreadyExist:
            return Response(status=409)

        return Response(status=200)

    def lists(self, req, dpid, **_kwargs):
        ports = self.tunnels.list_ports(int(dpid, 16))
        body = json.dumps(ports)

        return Response(content_type='application/json', body=body)

    def get(self, req, dpid, port_id, **_kwargs):
        try:
            remote_dpid = self.tunnels.get_remote_dpid(int(dpid, 16),
                                                       int(port_id))
        except ryu_exc.PortNotFound:
            return Response(status=404)
        body = json.dumps('%016x' % remote_dpid)

        return Response(content_type='application/json', body=body)

    def delete(self, req, dpid, port_id, **_kwargs):
        try:
            self.tunnels.delete_port(int(dpid, 16), int(port_id))
        except ryu_exc.PortNotFound:
            return Response(status=404)

        return Response(status=200)


class GRETunnelController(app_manager.RyuApp):
    _CONTEXTS = {
        'network': network.Network,
        'tunnels': tunnels.Tunnels,
        'wsgi': WSGIApplication
    }

    def __init__(self, *_args, **kwargs):
        super(GRETunnelController, self).__init__()
        self.nw = kwargs['network']
        self.tunnels = kwargs['tunnels']
        wsgi = kwargs['wsgi']
        mapper = wsgi.mapper

        wsgi.registory['TunnelKeyController'] = self.tunnels
        uri = '/v1.0/tunnels/gre'
        key_uri = uri + '/networks/{network_id}/key'
        mapper.connect('tunnel_key', key_uri,
                       controller=TunnelKeyController, action='lists',
                       conditions=dict(method=['GET', 'HEAD']))

        mapper.connect('tunnel_key', key_uri,
                       controller=TunnelKeyController, action='delete',
                       conditions=dict(method=['DELETE']))

        key_uri += '/{tunnel_key}'
        mapper.connect('tunnel_key', key_uri,
                       controller=TunnelKeyController, action='create',
                       conditions=dict(method=['POST']))

        mapper.connect('tunnel_key', key_uri,
                       controller=TunnelKeyController, action='update',
                       conditions=dict(method=['PUT']))

        wsgi.registory['TunnelPortController'] = self.tunnels
        sw_uri = uri + '/switches/{dpid}/ports'
        mapper.connect('tunnel_port', sw_uri,
                       controller=TunnelPortController, action='lists',
                       conditions=dict(method=['GET', 'HEAD']))

        sw_uri += '/{port_id}'
        mapper.connect('tunnel_port', sw_uri,
                       controller=TunnelPortController, action='get',
                       conditions=dict(method=['GET', 'HEAD']))

        mapper.connect('tunnel_port', sw_uri,
                       controller=TunnelPortController, action='delete',
                       conditions=dict(method=['DELETE']))

        sw_uri += '/{remote_dpid}'
        mapper.connect('tunnel_port', sw_uri,
                       controller=TunnelPortController, action='create',
                       conditions=dict(method=['POST']))

        mapper.connect('tunnel_port', sw_uri,
                       controller=TunnelPortController, action='update',
                       conditions=dict(method=['PUT']))

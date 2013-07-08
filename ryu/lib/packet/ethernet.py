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

import struct
from . import packet_base
from . import vlan
from . import mpls
from ryu.ofproto import ether


class ethernet(packet_base.PacketBase):
    """Ethernet header encoder/decoder class.

    An instance has the following attributes at least.
    __init__ takes the correspondig args in this order.

    =========== ====================
    Attribute   Description
    =========== ====================
    dst         destination address
    src         source address
    ethertype   ether type
    =========== ====================
    """

    _PACK_STR = '!6s6sH'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, dst, src, ethertype):
        super(ethernet, self).__init__()
        self.dst = dst
        self.src = src
        self.ethertype = ethertype

    @classmethod
    def parser(cls, buf):
        dst, src, ethertype = struct.unpack_from(cls._PACK_STR, buf)
        return (cls(dst, src, ethertype), ethernet.get_packet_type(ethertype),
                buf[ethernet._MIN_LEN:])

    def serialize(self, payload, prev):
        return struct.pack(ethernet._PACK_STR, self.dst, self.src,
                           self.ethertype)


# copy vlan _TYPES
ethernet._TYPES = vlan.vlan._TYPES
ethernet.register_packet_type(vlan.vlan, ether.ETH_TYPE_8021Q)
ethernet.register_packet_type(mpls.mpls, ether.ETH_TYPE_MPLS)

from unittest import TestCase

from nose.tools import ok_

from ryu.lib.packet import ethernet, ipv4, packet, tcp, udp
from ryu.lib.packet.in_proto import IPPROTO_TCP, IPPROTO_UDP

from flowsieve.acl.service_acl import ServiceACL


class ServiceACLTestCase(TestCase):
    def _get_tp_pkt(self, proto=IPPROTO_TCP, src_port=34567, dst_port=80):
        pkt = packet.Packet()

        pkt.add_protocol(ethernet.ethernet())
        pkt.add_protocol(ipv4.ipv4(proto=proto))
        if proto == IPPROTO_TCP:
            pkt.add_protocol(tcp.tcp(src_port=src_port, dst_port=dst_port))
        elif proto == IPPROTO_UDP:
            pkt.add_protocol(udp.udp(src_port=src_port, dst_port=dst_port))

        return pkt

    def test_allowed_services(self):
        acl = ServiceACL(service_default="deny",
                         allowed_services=["tcp/80", "udp/53"])
        acl.build_service_set()

        pkt = self._get_tp_pkt(proto=IPPROTO_TCP, dst_port=80)
        ok_(acl.allows_packet(pkt, None))

        pkt = self._get_tp_pkt(proto=IPPROTO_TCP, dst_port=21)
        ok_(not acl.allows_packet(pkt, None))

        pkt = self._get_tp_pkt(proto=IPPROTO_UDP, dst_port=53)
        ok_(acl.allows_packet(pkt, None))

        pkt = self._get_tp_pkt(proto=IPPROTO_UDP, dst_port=123)
        ok_(not acl.allows_packet(pkt, None))

    def test_default_deny(self):
        acl = ServiceACL(service_default="deny")
        acl.build_service_set()

        pkt = self._get_tp_pkt(proto=IPPROTO_TCP, dst_port=25)
        ok_(not acl.allows_packet(pkt, None))

        pkt = self._get_tp_pkt(proto=IPPROTO_TCP, dst_port=110)
        ok_(not acl.allows_packet(pkt, None))

        pkt = self._get_tp_pkt(proto=IPPROTO_TCP, dst_port=123)
        ok_(not acl.allows_packet(pkt, None))

    def test_default_allow(self):
        acl = ServiceACL(service_default="allow")
        acl.build_service_set()

        pkt = self._get_tp_pkt(proto=IPPROTO_TCP, dst_port=25)
        ok_(acl.allows_packet(pkt, None))

        pkt = self._get_tp_pkt(proto=IPPROTO_TCP, dst_port=110)
        ok_(acl.allows_packet(pkt, None))

        pkt = self._get_tp_pkt(proto=IPPROTO_TCP, dst_port=123)
        ok_(acl.allows_packet(pkt, None))

    def test_denied_services(self):
        acl = ServiceACL(service_default="allow",
                         denied_services=["udp/53", "udp/514"])
        acl.build_service_set()

        pkt = self._get_tp_pkt(proto=IPPROTO_TCP, dst_port=80)
        ok_(acl.allows_packet(pkt, None))

        pkt = self._get_tp_pkt(proto=IPPROTO_TCP, dst_port=21)
        ok_(acl.allows_packet(pkt, None))

        pkt = self._get_tp_pkt(proto=IPPROTO_UDP, dst_port=53)
        ok_(not acl.allows_packet(pkt, None))

        pkt = self._get_tp_pkt(proto=IPPROTO_UDP, dst_port=514)
        ok_(not acl.allows_packet(pkt, None))

    def test_invalid_default(self):
        acl = ServiceACL(service_default="deni")
        acl.build_service_set()

        pkt = self._get_tp_pkt(proto=IPPROTO_TCP, dst_port=25)
        ok_(acl.allows_packet(pkt, None))

        pkt = self._get_tp_pkt(proto=IPPROTO_TCP, dst_port=110)
        ok_(acl.allows_packet(pkt, None))

        pkt = self._get_tp_pkt(proto=IPPROTO_TCP, dst_port=123)
        ok_(acl.allows_packet(pkt, None))

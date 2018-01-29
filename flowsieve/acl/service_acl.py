import socket

from flowsieve.acl.acl_result import ACLResult, PacketMatch
from flowsieve.acl.base_acl import BaseACL
from flowsieve.acl.service_set import ServiceSet

from ryu.lib.packet import ethernet, ipv4, tcp, udp
from ryu.lib.packet.ether_types import ETH_TYPE_IP
from ryu.lib.packet.in_proto import IPPROTO_TCP, IPPROTO_UDP


class ServiceACL(BaseACL):
    def __init__(self, **kwargs):
        super(ServiceACL, self).__init__(**kwargs)
        self.allowed_services = [s for s in [
            Service.from_str(s) for s in kwargs.get("allowed_services", [])]
            if s is not None]
        self.denied_services = [s for s in [
            Service.from_str(s) for s in kwargs.get("denied_services", [])]
            if s is not None]
        self.default = kwargs.get("service_default", "allow")
        self.service_set = ServiceSet.empty()

    def load_relations(self, user_store):
        self.build_service_set()

    def build_service_set(self):
        self.service_set = ServiceSet.whole()

        default_str_low = self.default.lower()
        if default_str_low == "deny":
            self.service_set = ServiceSet.empty()
        elif default_str_low == "allow":
            self.service_set = ServiceSet.whole()
        elif default_str_low == "inherit" and self.parent is not None:
            self.parent.build_service_set()
            self.service_set = self.parent.service_set
        else:
            self._logger.warning("Unknown service_default value %s",
                                 self.default)

        self.service_set += ServiceSet(services=self.allowed_services)
        self.service_set -= ServiceSet(services=self.denied_services)

    def allows_packet(self, pkt, src_user):
        if pkt is None:
            return ACLResult(src_user in self.service_set, PacketMatch())

        eth = pkt.get_protocol(ethernet.ethernet)
        iph = pkt.get_protocol(ipv4.ipv4)
        tcph = pkt.get_protocol(tcp.tcp)
        udph = pkt.get_protocol(udp.udp)

        # This is not a TCP/IP packet
        if iph is None:
            return ACLResult(True, PacketMatch(dl_type=eth.ethertype))
        elif tcph is None and udph is None:
            return ACLResult(True, PacketMatch(dl_type=ETH_TYPE_IP,
                                               nw_proto=iph.proto))

        match = PacketMatch(dl_type=ETH_TYPE_IP)

        if tcph is not None:
            service = Service("tcp", tcph.dst_port)
            match += PacketMatch(nw_proto=IPPROTO_TCP, tp_dst=tcph.dst_port)
        elif udph is not None:
            service = Service("udp", udph.dst_port)
            match += PacketMatch(nw_proto=IPPROTO_UDP, tp_dst=udph.dst_port)

        return ACLResult(service in self.service_set, match)

    def __repr__(self):
        return "<ServiceACL allowed_services={0}, denied_services={1}>".format(
            self.allowed_services, self.denied_services
        )


class Service(object):
    @classmethod
    def from_str(cls, s):
        try:
            proto, port = s.split("/")

            if port.isdigit():
                port = int(port)
            else:
                port = socket.getservbyname(port, proto)
        except:
            return None

        return Service(proto, port)

    def __init__(self, proto, port):
        self.proto = proto
        self.port = port

    def __eq__(self, other):
        return self.proto == other.proto and self.port == other.port

    def __hash__(self):
        return hash((self.proto, self.port))

    def __repr__(self):
        return "<Service {0}/{1}>".format(self.proto, self.port)

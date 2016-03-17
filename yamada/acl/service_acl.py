import logging

from ryu.lib.packet import ethernet, ipv4, tcp, udp
from ryu.lib.packet.ether_types import ETH_TYPE_IP
from ryu.lib.packet.in_proto import IPPROTO_TCP, IPPROTO_UDP

from yamada.acl.acl_result import ACLResult, PacketMatch
from yamada.acl.base_acl import BaseACL
from yamada.acl.service_set import ServiceSet


class ServiceACL(BaseACL):
    def __init__(self, **kwargs):
        super(ServiceACL, self).__init__(**kwargs)
        self.allowed_services = [s for s in [
            Service.from_str(s) for s in kwargs.get("allowed_services", [])]
            if s is not None]
        self.denied_services = [s for s in [
            Service.from_str(s) for s in kwargs.get("denied_services", [])]
            if s is not None]
        self.default = kwargs.get("service_default", "deny")
        self.service_set = ServiceSet.empty()

    def load_relations(self, user_store):
        self.build_service_set()

    def build_service_set(self):
        self.service_set = ServiceSet.empty()

        default_str_low = self.default.lower()
        if default_str_low == "deny":
            self.service_set = ServiceSet.empty()
        elif default_str_low == "allow":
            self.service_set = ServiceSet.whole()
        elif default_str_low == "inherit" and self.parent is not None:
                self.parent.build_service_set()
                self.service_set = self.parent.service_set

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
            service = Service(TP_PROTO_TCP, tcph.dst_port)
            match += PacketMatch(nw_proto=IPPROTO_TCP, tp_dst=service.port)
        elif udph is not None:
            service = Service(TP_PROTO_UDP, udph.dst_port)
            match += PacketMatch(nw_proto=IPPROTO_UDP, tp_dst=service.port)

        return ACLResult(service in self.service_set, match)

    def __repr__(self):
        return "<ServiceACL allowed_services={0}, denied_services={1}>".format(
            self.allowed_services, self.denied_services
        )


TP_PROTO_TCP = "tcp"
TP_PROTO_UDP = "udp"


class Service(object):
    def __init__(self, proto, port):
        self.proto = proto
        self.port = port

    @classmethod
    def from_str(cls, s):
        logger = logging.getLogger(cls.__name__)
        splitted = s.split("/")
        if len(splitted) != 2:
            logger.warning("Service definition %s is malformed", s)
            return None

        proto = splitted[0].lower()
        if proto not in [TP_PROTO_TCP, TP_PROTO_UDP]:
            logger.warning("Service protocol %s is unknwon", proto)
            return None

        try:
            port = int(splitted[1])
        except ValueError:
            logger.warning("Service port %s is not a number", splitted[1])
            return None

        if port < 1 or port > 65535:
            logger.warning("Service port number %s is out of range", port)
            return None

        return Service(proto, port)

    def __eq__(self, other):
        return self.proto == other.proto and self.port == other.port

    def __hash__(self):
        return hash((self.proto, self.port))

    def __repr__(self):
        return "<Service {0}/{1}>".format(self.proto, self.port)

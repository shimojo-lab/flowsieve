import linecache
import logging

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

# Protocol alias
TP_PROTO_TCP = 1
TP_PROTO_UDP = 2
PROTO_DDP = 3
PROTO_SCTP = 4


class Service(object):
    ETC_SERVICE_FILE = "/etc/services"
    extracted_service = []
    extracted_port = []
    extracted_proto = []
    logger = logging.getLogger(__name__)
    service_file = []

    @classmethod
    def read_etc_service(cls):
        if cls.service_file != []:
            return
        try:
            cls.service_file = linecache.getlines(cls.ETC_SERVICE_FILE)
            cls.logger.debug("Service_file is ready")
            cls.parse_file()
        except IOError:
            cls.logger.error("Could not open %s" % cls.ETC_SERVICE_FILE)
            return None

    @classmethod
    def parse_file(cls):
        import re
        for line in cls.service_file:
            if line[0].isalpha():
                # ignore blank line and comment
                remove_comment = line.split("#")[0]
                # discard inline comment
                splitted_line = re.split(" |\t|\n", remove_comment)
                # split the line by space/tab/change line
                for each in splitted_line:
                    if each != "":
                        if len(each.split("/")) == 1:
                            # there is no '/' so we got a service
                            cls.extracted_service.append(each)
                        elif len(each.split("/")) == 2:
                            # we found a '/', it would be port/proto
                            if each.split("/")[0].isdigit():
                                # got a valid port, then check proto,
                                # it would be too long if two if(s)
                                # were mixed(?)
                                if each.split("/")[1] in [
                                        "tcp", "udp",
                                        "ddp", "sctp"]:
                                    cls.extracted_port.append(
                                        int(each.split("/")[0]))
                                    cls.extracted_proto.append(
                                        cls.proto_to_int(each.split("/")[1]))
                                else:
                                    cls.logger.warning(
                                        "Protocol %s is unknown" %
                                        each.split("/")[1])
                            else:
                                cls.logger.warning(
                                    "Port number %s is unknown" %
                                    each.split("/")[0])
                            break
                        else:
                            # too many '/', it would be a mistake
                            cls.logger.warning(
                                "This line %s is malformed:" %
                                each)
        return cls.service_file

    @classmethod
    def proto_to_int(cls, each):
        if each == "tcp":
            return TP_PROTO_TCP
        if each == "udp":
            return TP_PROTO_UDP
        if each == "ddp":
            return PROTO_DDP
        if each == "sctp":
            return PROTO_SCTP
        else:
            cls.logger.warning(
                "Protocol %s is unknown" % each)

    @classmethod                                 # deal with proto ddp & sctp
    def map_ddp_sctp_by_port(cls, port, proto):  # find proto first, then port
        if proto in cls.extracted_proto:         # because they overlaps some
            if proto == PROTO_DDP:               # ports with TCP & UDP
                service_index = cls.extracted_proto.index(PROTO_DDP)
            else:
                service_index = cls.extracted_proto.index(PROTO_SCTP)
        else:
            cls.logger.warning(
                "Combination %s/%s is not in the Service list" %
                (proto, port))
            return None
        while service_index < len(cls.extracted_service):
            if cls.extracted_proto[service_index] == proto:
                if cls.extracted_port[service_index] == port:
                    return Service(proto, port)
                else:
                    service_index += 1
            else:
                cls.logger.warning(
                    "Combination %s/%s is not in the Service list" %
                    (proto, port))
                return None

    @classmethod
    def map_ddp_sctp_by_service(cls, service, proto):  # deal with ddp & sctp
        if proto in cls.extracted_proto:               # like the method above
            if proto == PROTO_DDP:
                service_index = cls.extracted_proto.index(PROTO_DDP)
            else:
                service_index = cls.extracted_proto.index(PROTO_SCTP)
        else:
            cls.logger.warning(
                "Combination %s/%s is not in the Service list" %
                (proto, service))
            return None
        while service_index < len(cls.extracted_service):
            if cls.extracted_proto[service_index] == proto:
                if cls.extracted_service[service_index] == service:
                    port = cls.extracted_port[service_index]
                    return Service(proto, port)
                else:
                    service_index += 1
            else:
                cls.logger.warning(
                    "Combination %s/%s is not in the Service list" %
                    (proto, service))
                return None

    @classmethod
    def map_by_port(cls, port, proto):  # find port first, then match proto
        if port in cls.extracted_port:
            service_index = cls.extracted_port.index(port)
            while service_index < len(cls.extracted_service):
                if cls.extracted_port[service_index] == port:
                    if cls.extracted_proto[service_index] == proto:
                        return Service(proto, port)
                    else:
                        service_index += 1
                else:
                    cls.logger.warning(
                        "Combination %s/%s is not in the Service list" %
                        (proto, port))
                    return None
        else:
            cls.logger.warning(
                "Combination %s/%s is not in the Service list" %
                (proto, port))
            return None

    @classmethod
    def map_by_service(cls, service, proto):  # find service first,
        if service in cls.extracted_service:  # then match proto
            service_index = cls.extracted_service.index(service)
            while service_index < len(cls.extracted_service):
                if cls.extracted_service[service_index] == service:
                    if cls.extracted_proto[service_index] == proto:
                        port = cls.extracted_port[service_index]
                        return Service(proto, port)
                    else:
                        service_index += 1
                else:
                    cls.logger.warning(
                        "Combination %s/%s is not in the Service list" %
                        (proto, service))
                    return None
        else:
            cls.logger.warning(
                "Combination %s/%s is not in the Service list" %
                (proto, service))
            return None

    @classmethod
    def from_str(cls, s):
        if s is None:
            cls.logger.warning("Cannot parse None")
            return None
        splitted = s.split("/")
        if len(splitted) != 2:
            cls.logger.warning("Service definition [%s] is malformed", s)
            return None
        proto = splitted[0].lower()
        proto = cls.proto_to_int(proto)
        port_or_service = splitted[1]
        if proto in [PROTO_DDP, PROTO_SCTP]:
            if port_or_service.isdigit():
                port = int(port_or_service)
                return cls.map_ddp_sctp_by_port(port, proto)
            else:
                service = str(port_or_service)
                return cls.map_ddp_sctp_by_service(service, proto)
        elif proto in [TP_PROTO_TCP, TP_PROTO_UDP]:
            if port_or_service.isdigit():
                port = int(port_or_service)
                return cls.map_by_port(port, proto)
            else:
                service = str(port_or_service)
                return cls.map_by_service(service, proto)
        else:
            cls.logger.warning("Service protocol [%s] is unknwon", proto)
            return None

    def __init__(self, proto, port):
        self.proto = proto
        self.port = port

    def __eq__(self, other):
        return self.proto == other.proto and self.port == other.port

    def __hash__(self):
        return hash((self.proto, self.port))

    def __repr__(self):
        return "<Service {0}/{1}>".format(self.proto, self.port)

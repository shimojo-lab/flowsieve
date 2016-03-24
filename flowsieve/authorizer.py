"""
Extensible Authorizer
"""

import logging
import operator
from itertools import imap

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.mac import BROADCAST_STR
from ryu.lib.packet import ethernet, packet

from flowsieve import events
from flowsieve.acl.acl_result import ACLResult
from flowsieve.packet.eapol import ETH_TYPE_EAPOL
from flowsieve.secure_switch import SecureSwitch
from flowsieve.user_store import UserStore

from yaml import YAMLError, load


class Authorizer(app_manager.RyuApp):
    COOKIE_AUTHORIZER = 0xf200
    COOKIE_DROP = COOKIE_AUTHORIZER | 0x01

    def __init__(self, *args, **kwargs):
        super(Authorizer, self).__init__(*args, **kwargs)
        self._mac_to_users = {}
        self._authenticated_ports = set()
        self._user_store = UserStore.get_instance()
        self._topology = Topology()

    def _get_user_by_mac(self, mac):
        """Get user object by source MAC address"""
        if mac not in self._mac_to_users:
            return None

        user_name = self._mac_to_users[mac]

        return self._user_store.get_user(user_name)

    def _install_drop_flow_to_port(self, dp, port_no):
        """Install flow rules to drop all packets to port_no
        """
        ofproto = dp.ofproto
        ofproto_parser = dp.ofproto_parser

        match = ofproto_parser.OFPMatch(in_port=port_no)
        mod = dp.ofproto_parser.OFPFlowMod(
            datapath=dp, match=match, cookie=Authorizer.COOKIE_DROP,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=0x0000,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=[])
        dp.send_msg(mod)

    def _delete_switch_flows(self, dp, port_no):
        """Delete L2 switch flows on EAPOL Logoff
        """
        ofproto = dp.ofproto
        ofproto_parser = dp.ofproto_parser

        match_in = ofproto_parser.OFPMatch(in_port=port_no)
        mod_inport = dp.ofproto_parser.OFPFlowMod(
            datapath=dp, match=match_in, cookie=SecureSwitch.COOKIE_FORWARD,
            command=ofproto.OFPFC_DELETE)
        dp.send_msg(mod_inport)

        match_out = ofproto_parser.OFPMatch()
        mod_outport = dp.ofproto_parser.OFPFlowMod(
            datapath=dp, match=match_out, cookie=SecureSwitch.COOKIE_FORWARD,
            command=ofproto.OFPFC_DELETE, out_port=port_no)
        dp.send_msg(mod_outport)

    def _get_dpset(self):
        return app_manager.lookup_service_brick("dpset")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dpid = msg.datapath.id
        port = msg.in_port

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype != ETH_TYPE_EAPOL:
            if not self._is_allowed_port(dpid, port):
                self._install_drop_flow_to_port(msg.datapath, port)

    @set_ev_cls(events.EventPortAuthorized)
    def _event_port_authorized_handler(self, ev):
        self._mac_to_users[ev.mac] = ev.user_name
        self._authenticated_ports.add((ev.dpid, ev.port))

        dp = self._get_dpset().get(ev.dpid)
        if dp is None:
            return
        ofproto_parser = dp.ofproto_parser
        ofproto = dp.ofproto

        match = ofproto_parser.OFPMatch(in_port=ev.port)
        mod = dp.ofproto_parser.OFPFlowMod(
            datapath=dp, match=match, cookie=Authorizer.COOKIE_DROP,
            command=ofproto.OFPFC_DELETE)
        dp.send_msg(mod)

    @set_ev_cls(events.EventPortLoggedOff)
    def _event_port_loggedoff_handler(self, ev):
        if ev.mac in self._mac_to_users:
            del self._mac_to_users[ev.mac]
        self._authenticated_ports.discard((ev.dpid, ev.port))

        dp = self._get_dpset().get(ev.dpid)
        if dp is None:
            return
        self._delete_switch_flows(dp, ev.port)

    def _is_allowed_port(self, dpid, port):
        return (dpid, port) in self._authenticated_ports or \
               (dpid, port) in self._topology.trusted_ports

    @set_ev_cls(events.AuthorizeRequest)
    def _authorize_request_handler(self, req):
        pkt = packet.Packet(req.msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        src = eth.src
        dst = eth.dst
        dpid = req.msg.datapath.id
        port = req.msg.in_port

        src_user = self._get_user_by_mac(src)
        dst_user = self._get_user_by_mac(dst)

        result = ACLResult(False)

        if not self._is_allowed_port(dpid, port):
            pass

        elif src_user is not None and dst_user is not None:
            acl_results = imap(lambda acl: acl.allows_packet(pkt, src_user),
                               dst_user.acls.itervalues())
            result = reduce(operator.add, acl_results)

        if dst == BROADCAST_STR:
            result = ACLResult(True)

        reply = events.AuthorizeReply(req.dst, result)
        self.reply_to_request(req, reply)


class Topology(object):
    DEFAULT_TOPOLOGY_CONF_FILE = "conf/topology.yml"

    def __init__(self, file_name=None):
        super(Topology, self).__init__()
        if file_name is None:
            file_name = self.__class__.DEFAULT_TOPOLOGY_CONF_FILE
        self.config_file = file_name
        self._logger = logging.getLogger(self.__class__.__name__)
        self.trusted_ports = set()

        self._read_config_file()

    def get_user(self, user_name):
        assert isinstance(user_name, basestring)

        return self.users.get(user_name)

    def _read_config_file(self):
        try:
            data = load(file(self.config_file))
        except IOError:
            self._logger.error("Could not open %s", self.config_file)
            return
        except YAMLError:
            self._logger.error("Error while parsing %s", self.user_role_file)
            return

        if "switches" in data:
            self._logger.info("Reading switch data")
            self._read_switch_data(data["switches"])

    def _read_switch_data(self, data):
        for item in data:
            if "dpid" not in item:
                self.warning("DPID not defined")
                continue
            try:
                dpid = int(item["dpid"])
            except ValueError:
                self.warning("%s is not a valid DPID", item["data"])
                continue

            if "trusted_ports" in item:
                trusted_ports = item["trusted_ports"]
                for port in trusted_ports:
                    try:
                        port_num = int(port)
                    except ValueError:
                        self.warning("%s is not a valid port number", port)
                        continue

                    self.trusted_ports.add((dpid, port_num))

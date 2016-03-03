"""
Yamada 802.1X Authenticator
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

from yamada import eap, eapol, eap_md5_sm, simple_switch


class Authenticator(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    _EVENTS = [eap_md5_sm.EventStartEAP, eap_md5_sm.EventStartEAPMD5Challenge,
               eap_md5_sm.EventFinishEAPMD5Challenge]
    _CONTEXTS = {
        "eap_md5_sm": eap_md5_sm.EAPMD5StateMachine,
        "simple_switch": simple_switch.SimpleSwitch
    }

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self._dps = {}

    def _install_eapol_flow(self, dp):
        ofproto = dp.ofproto
        ofproto_parser = dp.ofproto_parser

        match = ofproto_parser.OFPMatch(dl_type=eapol.ETH_TYPE_EAPOL)
        actions = [ofproto_parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]

        mod = dp.ofproto_parser.OFPFlowMod(
            datapath=dp, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=0xffff,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER,
                                                DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if dp.id is None:
                return
            self.logger.info("Datapath %016x connected", dp.id)
            self._dps[dp.id] = dp
            self._install_eapol_flow(dp)
        elif ev.state == DEAD_DISPATCHER:
            if dp.id is None:
                return
            if dp.id in self._dps:
                del self._dps[dp.id]

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        dpid = dp.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype != eapol.ETH_TYPE_EAPOL:
            # Ignore packets other than EAPOL
            return
        dst = eth.dst
        src = eth.src

        print pkt

        eapol_msg = pkt.get_protocol(eapol.eapol)

        sm_ev = None

        if eapol_msg.type_ == eapol.EAPOL_TYPE_START:
            sm_ev = eap_md5_sm.EventStartEAP(dpid, src, dst, msg.in_port)

        elif eapol_msg.type_ == eapol.EAPOL_TYPE_EAP:
            eap_msg = pkt.get_protocol(eap.eap)
            if eap_msg.code == eap.EAP_CODE_RESPONSE:

                if eap_msg.type_ == eap.EAP_TYPE_IDENTIFY:
                    sm_ev = eap_md5_sm.EventStartEAPMD5Challenge(
                            dpid, msg.in_port, eap_msg.data.identity)

                elif eap_msg.type_ == eap.EAP_TYPE_MD5_CHALLENGE:
                    sm_ev = eap_md5_sm.EventFinishEAPMD5Challenge(
                            dpid, msg.in_port, eap_msg.data.challenge,
                            eap_msg.identifier)

        if sm_ev is not None:
            self.send_event_to_observers(sm_ev)

    @set_ev_cls(eap_md5_sm.EventOutputEAPOL)
    def _event_output_eapol_handler(self, ev):
        ev.pkt.serialize()

        dp = self._dps.get(ev.dpid)
        if dp is None:
            return
        ofproto_parser = dp.ofproto_parser
        ofproto = dp.ofproto

        actions = [ofproto_parser.OFPActionOutput(ev.port)]
        out = ofproto_parser.OFPPacketOut(
            datapath=dp,
            in_port=ofproto.OFPP_NONE,
            actions=actions,
            buffer_id=ofproto.OFP_NO_BUFFER,
            data=ev.pkt.data)
        dp.send_msg(out)

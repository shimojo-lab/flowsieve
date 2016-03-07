"""
Yamada 802.1X Authenticator
"""

from ryu.base import app_manager
from ryu.controller import ofp_event, dpset
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

from yamada import eap, eapol, eap_md5_method, eap_events, simple_switch


class Authenticator(app_manager.RyuApp):
    """802.1X Authenticator Application
    """
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    _EVENTS = [eap_events.EventStartEAPOL, eap_events.EventLogoffEAPOL,
               eap_events.EventStartEAPMD5Challenge,
               eap_events.EventFinishEAPMD5Challenge]
    _CONTEXTS = {
        "dpset": dpset.DPSet,
        "simple_switch": simple_switch.SimpleSwitch,
        "eap_md5_method": eap_md5_method.EAPMD5Method,
    }

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self._dps = kwargs["dpset"]

    def _install_eapol_flow(self, dp):
        """Install flow rules to forward EAPoL packets to the controller
        """
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

    @set_ev_cls(ofp_event.EventOFPStateChange, MAIN_DISPATCHER)
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if dp.id is None:
            return

        self.logger.info("Datapath %016x connected", dp.id)
        self._install_eapol_flow(dp)

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

        eapol_msg = pkt.get_protocol(eapol.eapol)

        sm_ev = None

        # We received an EAPoL start frame
        if eapol_msg.type_ == eapol.EAPOL_TYPE_START:
            sm_ev = eap_events.EventStartEAPOL(dpid, src, dst, msg.in_port)

        # We received an EAPoL logoff frame
        if eapol_msg.type_ == eapol.EAPOL_TYPE_LOGOFF:
            sm_ev = eap_events.EventLogoffEAPOL(dpid, msg.in_port)

        # We received an EAPoL EAP frame
        elif eapol_msg.type_ == eapol.EAPOL_TYPE_EAP:
            eap_msg = pkt.get_protocol(eap.eap)

            # This is an EAP Response packet
            if eap_msg.code == eap.EAP_CODE_RESPONSE:

                # This is a EAP Identify Response
                if eap_msg.type_ == eap.EAP_TYPE_IDENTIFY:
                    sm_ev = eap_events.EventStartEAPMD5Challenge(
                            dpid, msg.in_port, eap_msg.data.identity)

                # This is an EAP MD5 Challenge Response
                elif eap_msg.type_ == eap.EAP_TYPE_MD5_CHALLENGE:
                    sm_ev = eap_events.EventFinishEAPMD5Challenge(
                            dpid, msg.in_port, eap_msg.data.challenge,
                            eap_msg.identifier)

        if sm_ev is not None:
            self.send_event_to_observers(sm_ev)

    @set_ev_cls(eap_events.EventOutputEAPOL)
    def _event_output_eapol_handler(self, ev):
        """Output EAPoL frame from a specified datapath & port
        """
        ev.pkt.serialize()

        # The minimum size of an ethernet frame is 64 bytes,
        # including 4-byte CRC, which is added by the hardware.
        data_len = len(ev.pkt.data)
        pad_len = max(60 - data_len, 0)
        ev.pkt.data += "\x00" * pad_len

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

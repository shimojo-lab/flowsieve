"""
Yamada 802.1X Authenticator
"""

import md5
import struct

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

from yamada import eap, eapol


class Authenticator(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.dps = {}

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
            self.dps[dp.id] = dp
            self._install_eapol_flow(dp)
        elif ev.state == DEAD_DISPATCHER:
            if dp.id is None:
                return
            if dp.id in self.dps:
                del self.dps[dp.id]

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofproto = dp.ofproto
        ofproto_parser = dp.ofproto_parser
        dpid = dp.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype != eapol.ETH_TYPE_EAPOL:
            # Ignore packets other than EAPOL
            return
        dst = eth.dst
        src = eth.src

        self.logger.info("EAPOL packet in %s %s %s %s", dpid, src, dst, msg.in_port)
        print pkt

        eapol_msg = pkt.get_protocol(eapol.eapol)

        if eapol_msg.type_ == eapol.EAPOL_TYPE_START:
            resp = packet.Packet()
            resp.add_protocol(ethernet.ethernet(src=dst,
                                                dst=src,
                                                ethertype=eapol.ETH_TYPE_EAPOL))
            resp.add_protocol(eapol.eapol(type_=eapol.EAPOL_TYPE_EAP))
            resp.add_protocol(eap.eap(code=eap.EAP_CODE_REQUEST,
                                      type_=eap.EAP_TYPE_IDENTIFY))
            print resp
            resp.serialize()

            actions = [ofproto_parser.OFPActionOutput(msg.in_port)]
            out = ofproto_parser.OFPPacketOut(
                datapath=dp,
                in_port=ofproto.OFPP_NONE,
                actions=actions,
                buffer_id=ofproto.OFP_NO_BUFFER,
                data=resp.data)
            dp.send_msg(out)

        elif eapol_msg.type_ == eapol.EAPOL_TYPE_EAP:
            eap_msg = pkt.get_protocol(eap.eap)
            if eap_msg.code == eap.EAP_CODE_RESPONSE and eap_msg.type_ == eap.EAP_TYPE_IDENTIFY:
                resp = packet.Packet()
                resp.add_protocol(ethernet.ethernet(src=dst,
                                                    dst=src,
                                                    ethertype=eapol.ETH_TYPE_EAPOL))
                resp.add_protocol(eapol.eapol(type_=eapol.EAPOL_TYPE_EAP))
                resp.add_protocol(eap.eap(code=eap.EAP_CODE_REQUEST,
                                          type_=eap.EAP_TYPE_MD5_CHALLENGE,
                                          data=eap.eap_md5_challenge(challenge="aaaaaaaaaaaaaaaa")))
                print resp
                resp.serialize()

                actions = [ofproto_parser.OFPActionOutput(msg.in_port)]
                out = ofproto_parser.OFPPacketOut(
                    datapath=dp,
                    in_port=ofproto.OFPP_NONE,
                    actions=actions,
                    buffer_id=ofproto.OFP_NO_BUFFER,
                    data=resp.data)
                dp.send_msg(out)
            if eap_msg.code == eap.EAP_CODE_RESPONSE and eap_msg.type_ == eap.EAP_TYPE_MD5_CHALLENGE:
                m = md5.new()
                m.update(struct.pack("!B", eap_msg.identifier))
                m.update("TIS")
                m.update("aaaaaaaaaaaaaaaa")
                print repr(m.digest())

                #  if m.digest() == eap_msg.data.challenge:
                    #  result = eap.EAP_CODE_SUCCESS
                #  else:
                    #  result = eap.EAP_CODE_FAILURE

                resp = packet.Packet()
                resp.add_protocol(ethernet.ethernet(src=dst,
                                                    dst=src,
                                                    ethertype=eapol.ETH_TYPE_EAPOL))
                resp.add_protocol(eapol.eapol(type_=eapol.EAPOL_TYPE_EAP))
                resp.add_protocol(eap.eap(identifier=eap_msg.identifier, code=eap.EAP_CODE_SUCCESS))
                resp.serialize()

                actions = [ofproto_parser.OFPActionOutput(msg.in_port)]
                out = ofproto_parser.OFPPacketOut(
                    datapath=dp,
                    in_port=ofproto.OFPP_NONE,
                    actions=actions,
                    buffer_id=ofproto.OFP_NO_BUFFER,
                    data=resp.data)
                dp.send_msg(out)

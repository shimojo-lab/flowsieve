"""
State machine for EAP-MD5 authentication flow
"""

import struct
import md5

from ryu.base import app_manager
from ryu.controller.handler import set_ev_cls
from ryu.controller.event import EventBase
from ryu.lib.packet import packet, ethernet

from yamada import eap, eapol


class EventStartEAPOL(EventBase):
    """EAPoL start received
    """
    def __init__(self, dpid, src, dst, port):
        super(EventStartEAPOL, self).__init__()
        self.dpid = dpid
        self.src = src
        self.dst = dst
        self.port = port


class EventStartEAPMD5Challenge(EventBase):
    """EAP identify response received
    """
    def __init__(self, dpid, port, identity):
        super(EventStartEAPMD5Challenge, self).__init__()
        self.dpid = dpid
        self.port = port
        self.identity = identity


class EventFinishEAPMD5Challenge(EventBase):
    """EAP MD5 challenge response received
    """
    def __init__(self, dpid, port, challenge, identifier):
        super(EventFinishEAPMD5Challenge, self).__init__()
        self.dpid = dpid
        self.port = port
        self.challenge = challenge
        self.identifier = identifier


class EventOutputEAPOL(EventBase):
    """Request to send an EAPoL frame
    """
    def __init__(self, dpid, port, pkt):
        super(EventOutputEAPOL, self).__init__()
        self.dpid = dpid
        self.port = port
        self.pkt = pkt


EAPMD5_STAETE_IDLE = 0
EAPMD5_STAETE_IDENT = 1
EAPMD5_STAETE_CHALLENGE = 2


class EAPMD5Context(object):
    """Represents an EAP MD5 authentication context
    """
    def __init__(self, dpid, port, src, dst):
        super(EAPMD5Context, self).__init__()
        # The datapath we're working on
        self.dpid = dpid
        # The port number we're working on
        self.port = port
        # Supplicant MAC address
        self.src = src
        # Authenticator MAC address (likely to be a multicast address)
        self.dst = dst
        # MD5 challenge value
        self.challenge = ""
        # Identity
        self.identity = ""
        # Current state
        self.state = EAPMD5_STAETE_IDLE


class EAPMD5StateMachine(app_manager.RyuApp):
    _EVENTS = [EventOutputEAPOL]

    def __init__(self, *args, **kwargs):
        super(EAPMD5StateMachine, self).__init__(*args, **kwargs)
        self._contexts = {}

    @set_ev_cls(EventStartEAPOL)
    def _event_start_eap_handler(self, ev):
        """Received an EAPoL Start packet
        Reply with a EAP Request Identify packet
        """
        if (ev.dpid, ev.port) not in self._contexts:
            self._contexts[(ev.dpid, ev.port)] = EAPMD5Context(
                ev.dpid, ev.port, ev.src, ev.dst)
        ctx = self._contexts.get((ev.dpid, ev.port))

        if ctx.state != EAPMD5_STAETE_IDLE:
            return

        ctx.state = EAPMD5_STAETE_IDENT

        resp = packet.Packet()
        resp.add_protocol(ethernet.ethernet(src=ctx.dst, dst=ctx.src,
                                            ethertype=eapol.ETH_TYPE_EAPOL))
        resp.add_protocol(eapol.eapol(type_=eapol.EAPOL_TYPE_EAP))
        resp.add_protocol(eap.eap(code=eap.EAP_CODE_REQUEST,
                                  type_=eap.EAP_TYPE_IDENTIFY))

        self.send_event_to_observers(EventOutputEAPOL(ev.dpid, ev.port, resp))

    @set_ev_cls(EventStartEAPMD5Challenge)
    def _event_start_md5_challenge(self, ev):
        """Received an EAPoL Response Identify packet
        Reply with a EAP Request MD5 Challenge packet
        """
        ctx = self._contexts.get((ev.dpid, ev.port))
        if ctx is None or ctx.state != EAPMD5_STAETE_IDENT:
            # Unknown peer or inconsistent state
            return

        c = eap.eap_md5_challenge()

        ctx.identity = ev.identity
        ctx.challenge = c.challenge
        ctx.state = EAPMD5_STAETE_CHALLENGE

        resp = packet.Packet()
        resp.add_protocol(ethernet.ethernet(src=ctx.dst, dst=ctx.src,
                                            ethertype=eapol.ETH_TYPE_EAPOL))
        resp.add_protocol(eapol.eapol(type_=eapol.EAPOL_TYPE_EAP))
        resp.add_protocol(eap.eap(code=eap.EAP_CODE_REQUEST,
                                  type_=eap.EAP_TYPE_MD5_CHALLENGE,
                                  data=c))

        self.send_event_to_observers(EventOutputEAPOL(ev.dpid, ev.port, resp))

    @set_ev_cls(EventFinishEAPMD5Challenge)
    def _event_finish_eap_md5_challenge(self, ev):
        """Received an EAPoL Response MD5 Challenge packet
        Reply with a EAP Success/Failure packet
        """
        ctx = self._contexts.get((ev.dpid, ev.port), None)
        if ctx is None or ctx.state != EAPMD5_STAETE_CHALLENGE:
            # Unknown peer or inconsistent state
            return

        ctx.identifier = ev.identifier
        ctx.state = EAPMD5_STAETE_IDLE

        valid = self._check_challenge_response(ev.challenge, ctx.identifier,
                                               ctx.challenge, "TIS")
        if valid:
            code = eap.EAP_CODE_SUCCESS
        else:
            code = eap.EAP_CODE_FAILURE

        resp = packet.Packet()
        resp.add_protocol(ethernet.ethernet(src=ctx.dst, dst=ctx.src,
                                            ethertype=eapol.ETH_TYPE_EAPOL))
        resp.add_protocol(eapol.eapol(type_=eapol.EAPOL_TYPE_EAP))
        resp.add_protocol(eap.eap(identifier=ctx.identifier,
                                  code=code))

        self.send_event_to_observers(EventOutputEAPOL(ev.dpid, ev.port, resp))

    def _check_challenge_response(self, response, identifier, challenge,
                                  password):
        """Check if MD5 challenge response is correct
        """
        m = md5.new()
        m.update(struct.pack("!B", identifier))
        m.update(password)
        m.update(challenge)

        return m.digest() == response

"""
State machine for EAP-MD5 authentication flow
"""

import logging
import md5
import struct

from ryu.base import app_manager
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import ethernet, packet

from transitions import Machine

from flowsieve import eap_events, events
from flowsieve.packet import eap, eapol
from flowsieve.user_store import UserStore


class EAPMD5Context(object):
    """Represents an EAP MD5 authentication context
    """

    _STATES = ["idle", "ident", "challenge", "authenticated"]

    def __init__(self, dpid, port, host_mac, sw_mac):
        super(EAPMD5Context, self).__init__()
        # The datapath we're working on
        self.dpid = dpid
        # The port number we're working on
        self.port = port
        # Supplicant MAC address
        self.host_mac = host_mac
        # Authenticator MAC address (likely to be a multicast address)
        self.sw_mac = sw_mac
        # MD5 challenge value
        self.challenge = ""
        # Identity
        self.identity = ""

        # Logger
        self._logger = logging.getLogger(self.__class__.__name__)
        # State machine
        self._state_machine = Machine(model=self, states=EAPMD5Context._STATES,
                                      initial="idle")
        self._state_machine.add_transition("start_ident", "idle", "ident")
        self._state_machine.add_transition("start_challenge", "ident",
                                           "challenge")
        self._state_machine.add_transition("logon", "challenge",
                                           "authenticated")
        self._state_machine.add_transition("logoff", "*", "idle")

    def on_enter_challenge(self, identity, challenge):
        self.identity = identity
        self.challenge = challenge

    def on_enter_authenticated(self):
        self._logger.info("Authenticated user %s (%s) at port %d of"
                          " switch %016x", self.identity, self.host_mac,
                          self.port, self.dpid)


class EAPMD5Method(app_manager.RyuApp):
    """EAP-MD5 authentication method implementation
    """
    _EVENTS = [eap_events.EventOutputEAPOL, events.EventPortAuthorized,
               events.EventPortLoggedOff]

    def __init__(self, *args, **kwargs):
        super(EAPMD5Method, self).__init__(*args, **kwargs)
        self._contexts = {}
        self._user_store = UserStore.get_instance()

    @set_ev_cls(eap_events.EventStartEAPOL)
    def _event_start_eap_handler(self, ev):
        """Received an EAPoL Start packet
        Reply with an EAP Request Identify packet
        """
        if (ev.dpid, ev.port) not in self._contexts:
            ctx = EAPMD5Context(ev.dpid, ev.port, ev.src, ev.dst)

            self._contexts[(ev.dpid, ev.port)] = ctx

        ctx = self._contexts.get((ev.dpid, ev.port))

        if not ctx.is_idle():
            return
        ctx.start_ident()

        resp = packet.Packet()
        resp.add_protocol(ethernet.ethernet(src=ctx.sw_mac, dst=ctx.host_mac,
                                            ethertype=eapol.ETH_TYPE_EAPOL))
        resp.add_protocol(eapol.eapol(type_=eapol.EAPOL_TYPE_EAP))
        resp.add_protocol(eap.eap(code=eap.EAP_CODE_REQUEST,
                                  type_=eap.EAP_TYPE_IDENTIFY))

        self.send_event_to_observers(
            eap_events.EventOutputEAPOL(ev.dpid, ev.port, resp)
        )

    @set_ev_cls(eap_events.EventLogoffEAPOL)
    def _event_logoff_eap_handler(self, ev):
        """Received an EAPoL Logoff packet
        Reply with an EAP Request Identify packet
        """
        ctx = self._contexts.get((ev.dpid, ev.port))
        if ctx is None:
            return

        ctx.logoff()

        self.send_event_to_observers(
            events.EventPortLoggedOff(ev.dpid, ev.port, ctx.host_mac,
                                      ctx.identity)
        )

    @set_ev_cls(eap_events.EventStartEAPMD5Challenge)
    def _event_start_md5_challenge(self, ev):
        """Received an EAPoL Response Identify packet
        Reply with an EAP Request MD5 Challenge packet
        """
        ctx = self._contexts.get((ev.dpid, ev.port))
        if ctx is None or not ctx.is_ident():
            # Unknown peer or inconsistent state
            return

        c = eap.eap_md5_challenge()
        ctx.start_challenge(ev.identity, c.challenge)

        resp = packet.Packet()
        resp.add_protocol(ethernet.ethernet(src=ctx.sw_mac, dst=ctx.host_mac,
                                            ethertype=eapol.ETH_TYPE_EAPOL))
        resp.add_protocol(eapol.eapol(type_=eapol.EAPOL_TYPE_EAP))
        resp.add_protocol(eap.eap(code=eap.EAP_CODE_REQUEST,
                                  type_=eap.EAP_TYPE_MD5_CHALLENGE,
                                  data=c))

        self.send_event_to_observers(
            eap_events.EventOutputEAPOL(ev.dpid, ev.port, resp)
        )

    @set_ev_cls(eap_events.EventFinishEAPMD5Challenge)
    def _event_finish_eap_md5_challenge(self, ev):
        """Received an EAPoL Response MD5 Challenge packet
        Reply with an EAP Success/Failure packet
        """
        ctx = self._contexts.get((ev.dpid, ev.port))
        if ctx is None or not ctx.is_challenge():
            # Unknown peer or inconsistent state
            return

        user = self._user_store.get_user(ctx.identity)
        if user is not None:
            valid = self._check_challenge_response(ev.challenge, ev.identifier,
                                                   ctx.challenge,
                                                   user.password)
        else:
            valid = False

        if valid:
            code = eap.EAP_CODE_SUCCESS
            ctx.logon()
            self.send_event_to_observers(
                events.EventPortAuthorized(ev.dpid, ev.port, ctx.host_mac,
                                           ctx.identity)
            )
        else:
            code = eap.EAP_CODE_FAILURE
            ctx.logoff()

        resp = packet.Packet()
        resp.add_protocol(ethernet.ethernet(src=ctx.sw_mac, dst=ctx.host_mac,
                                            ethertype=eapol.ETH_TYPE_EAPOL))
        resp.add_protocol(eapol.eapol(type_=eapol.EAPOL_TYPE_EAP))
        resp.add_protocol(eap.eap(identifier=ev.identifier,
                                  code=code))

        self.send_event_to_observers(
            eap_events.EventOutputEAPOL(ev.dpid, ev.port, resp)
        )

    def _check_challenge_response(self, response, identifier, challenge,
                                  password):
        """Check if MD5 challenge response is correct
        """
        m = md5.new()
        m.update(struct.pack("!B", identifier))
        m.update(password)
        m.update(challenge)

        return m.digest() == response

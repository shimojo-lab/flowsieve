"""
Extensible Authorizer
"""

from ryu.base import app_manager
from ryu.controller.handler import set_ev_cls
from ryu.lib.mac import BROADCAST_STR
from ryu.lib.packet import ethernet, packet

from yamada import events, user_store


class Authorizer(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(Authorizer, self).__init__(*args, **kwargs)
        self._mac_to_users = {}
        self._user_store = user_store.UserStore()

    def _get_user_by_mac(self, mac):
        """Get user object by source MAC address"""
        if mac not in self._mac_to_users:
            return None

        user_name = self._mac_to_users[mac]

        return self._user_store.get_user(user_name)

    @set_ev_cls(events.EventPortAuthorized)
    def _event_port_authorized_handler(self, ev):
        self._mac_to_users[ev.mac] = ev.user_name

    @set_ev_cls(events.EventPortLoggedOff)
    def _event_port_loggedoff_handler(self, ev):
        if ev.mac in self._mac_to_users:
            del self._mac_to_users[ev.mac]

    @set_ev_cls(events.AuthorizeRequest)
    def _authorize_request_handler(self, req):
        pkt = packet.Packet(req.msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        src = eth.src
        dst = eth.dst

        src_user = self._get_user_by_mac(src)
        dst_user = self._get_user_by_mac(dst)

        result = False

        if src_user is not None and dst_user is not None:
            results = map(lambda acl: acl.allows_packet(pkt, src_user),
                          dst_user.acls.values())
            result = reduce(lambda a, b: a and b, results)

        if dst == BROADCAST_STR:
            result = True

        reply = events.AuthorizeReply(req.dst, result)
        self.reply_to_request(req, reply)


class ACLResult(object):
    def __init__(self, accept, match_rule):
        super(ACLResult, self).__init__()

    def __add__(self, other):
        pass

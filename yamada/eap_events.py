from ryu.controller.event import EventBase, EventReplyBase, EventRequestBase


class EventStartEAPOL(EventBase):
    """EAPoL start received
    """
    def __init__(self, dpid, src, dst, port):
        super(EventStartEAPOL, self).__init__()
        self.dpid = dpid
        self.src = src
        self.dst = dst
        self.port = port


class EventLogoffEAPOL(EventBase):
    """EAPoL logoff received
    """
    def __init__(self, dpid, port):
        super(EventLogoffEAPOL, self).__init__()
        self.dpid = dpid
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


class EventPortAuthorized(EventBase):
    """Activate authorized port
    """
    def __init__(self, dpid, port):
        super(EventPortAuthorized, self).__init__()
        self.dpid = dpid
        self.port = port


class EventPortLoggedOff(EventBase):
    """Port logged off
    """
    def __init__(self, dpid, port):
        super(EventPortLoggedOff, self).__init__()
        self.dpid = dpid
        self.port = port


class AuthorizeRequest(EventRequestBase):
    def __init__(self, msg):
        super(AuthorizeRequest, self).__init__()
        self.dst = "EAPMD5Method"
        self.msg = msg


class AuthorizeReply(EventReplyBase):
    def __init__(self, dst, result):
        super(AuthorizeReply, self).__init__(dst)
        self.result = result

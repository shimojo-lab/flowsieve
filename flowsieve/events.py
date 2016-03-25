from ryu.controller.event import EventBase, EventReplyBase, EventRequestBase


class EventPortAuthorized(EventBase):
    """Activate authorized port
    """
    def __init__(self, dpid, port, mac, user_name):
        super(EventPortAuthorized, self).__init__()
        self.dpid = dpid
        self.port = port
        self.mac = mac
        self.user_name = user_name


class EventPortLoggedOff(EventBase):
    """Port logged off
    """
    def __init__(self, dpid, port, mac, user_name):
        super(EventPortLoggedOff, self).__init__()
        self.dpid = dpid
        self.port = port
        self.mac = mac
        self.user_name = user_name


class AuthorizeRequest(EventRequestBase):
    def __init__(self, msg):
        super(AuthorizeRequest, self).__init__()
        self.dst = "Authorizer"
        self.msg = msg


class AuthorizeReply(EventReplyBase):
    def __init__(self, dst, result):
        super(AuthorizeReply, self).__init__(dst)
        self.result = result

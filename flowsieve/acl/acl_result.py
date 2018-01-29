from ryu.lib.mac import haddr_to_bin
from ryu.lib.stringify import StringifyMixin
from ryu.ofproto.ofproto_v1_0_parser import OFPMatch


class PacketMatch(StringifyMixin):
    def __init__(self, in_port=None, dl_src=None, dl_dst=None, dl_vlan=None,
                 dl_vlan_pcp=None, dl_type=None, nw_tos=None, nw_proto=None,
                 nw_src=None, nw_dst=None, tp_src=None, tp_dst=None,
                 nw_src_mask=None, nw_dst_mask=None):
        super(PacketMatch, self).__init__()

        self.in_port = in_port
        self.dl_src = dl_src
        self.dl_dst = dl_dst
        self.dl_vlan = dl_vlan
        self.dl_vlan_pcp = dl_vlan_pcp
        self.dl_type = dl_type
        self.nw_tos = nw_tos
        self.nw_proto = nw_proto
        self.nw_src = nw_src
        self.nw_dst = nw_dst
        self.tp_src = tp_src
        self.tp_dst = tp_dst
        self.nw_src_mask = nw_src_mask
        self.nw_dst_mask = nw_dst_mask

    def __add__(self, other):
        assert isinstance(other, self.__class__)

        kwargs = {}
        for k, v in self.__dict__.items():
            kwargs[k] = getattr(self, k) or getattr(other, k)

        return PacketMatch(**kwargs)

    def to_ofp_match(self):
        kwargs = self.__dict__.copy()

        if self.dl_src is not None:
            kwargs["dl_src"] = haddr_to_bin(self.dl_src)
        if self.dl_dst is not None:
            kwargs["dl_dst"] = haddr_to_bin(self.dl_dst)

        return OFPMatch(**kwargs)


class ACLResult(object):
    def __init__(self, accept, match=PacketMatch()):
        super(ACLResult, self).__init__()
        self.accept = accept
        self.match = match

    def __add__(self, other):
        assert isinstance(other, self.__class__)

        return ACLResult(self.accept and other.accept,
                         self.match + other.match)

    def __bool__(self):
        return self.accept

import struct

from ryu.lib.packet import packet_base
from ryu.lib.packet.ethernet import ethernet

from yamada.eap import eap

ETH_TYPE_EAPOL = 0x888e
EAPOL_TYPE_EAP = 0x00
EAPOL_TYPE_START = 0x01
EAPOL_TYPE_LOGOFF = 0x02
EAPOL_TYPE_KEY = 0x03
EAPOL_TYPE_ASF_ALERT = 0x04
EAPOL_TYPE_MKA = 0x05
EAPOL_TYPE_GENENRIC_ANNOUCEMENT = 0x06
EAPOL_TYPE_SPECIFIC_ANNOUNCEMENT = 0x07
EAPOL_TYPE_ANNOUNCEMENT_REQUEST = 0x08


class eapol(packet_base.PacketBase):
    """Encoder/Decoder for EAPoL (EAP over LAN) packets
    """
    _PACK_STR = "!BBH"
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, version=0x02, type_=EAPOL_TYPE_EAP, length=0):
        super(eapol, self).__init__()
        self.version = version
        self.type_ = type_
        self.length = length

    def __len__(self):
        return self._MIN_LEN

    def __eq__(self, other):
        if other is None or type(self) != type(other):
            return False
        return self.__dict__ == other.__dict__

    @classmethod
    def parser(cls, buf):
        (version, type_, length) = struct.unpack_from(eapol._PACK_STR, buf)
        msg = cls(version, type_, length)

        if type_ == EAPOL_TYPE_START:
            return msg, None, None
        elif type_ == EAPOL_TYPE_EAP:
            return msg, eap, buf[eapol._MIN_LEN:eapol._MIN_LEN+length]
        elif type_ == EAPOL_TYPE_LOGOFF:
            return msg, None, None

    def serialize(self, payload, prev):
        if self.length == 0:
            self.length = len(payload)

        hdr = bytearray(struct.pack(self._PACK_STR, self.version, self.type_,
                        self.length))
        return hdr

ethernet.register_packet_type(eapol, ETH_TYPE_EAPOL)

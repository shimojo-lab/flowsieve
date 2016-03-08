from nose.tools import eq_

from ryu.lib.packet import packet

from yamada.eap import eap
from yamada.eapol import eapol

EAPOL_TEST_CASES = [
    ([eapol(version=0x01, type_=0x01)], "\x01\x01\x00\x00"),
    ([eapol(version=0x02, type_=0x01)], "\x02\x01\x00\x00"),
    ([eapol(version=0x02, type_=0x02)], "\x02\x02\x00\x00"),
    ([eapol(version=0x02, type_=0x00, length=4),
      eap(code=0x03, length=4, identifier=0x12)],
     "\x02\x00\x00\x04" "\x03\x12\x00\x04")
]


def test_eapol():
    for (protocols, binary) in EAPOL_TEST_CASES:
        yield check_parse_eapol, protocols, binary
        yield check_serialize_eapol, protocols, binary


def check_parse_eapol(protocols, b):
    pkt = packet.Packet(data=b, protocols=None, parse_cls=eapol)
    pkt_eapol = pkt.get_protocol(eapol)

    eq_(pkt_eapol, protocols[0])


def check_serialize_eapol(protocols, b):
    pkt = packet.Packet()
    for p in protocols:
        pkt.add_protocol(p)
    pkt.serialize()

    eq_(pkt.data, b)

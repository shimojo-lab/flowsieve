from flowsieve.packet.eap import eap, eap_identify, eap_md5_challenge

from nose.tools import eq_

from ryu.lib.packet import packet

EAP_TEST_CASES = [
    # EAP Sucess
    (eap(code=0x03, identifier=0x12, length=4), "\x03\x12\x00\x04"),
    # EAP Failure
    (eap(code=0x04, identifier=0x34, length=4), "\x04\x34\x00\x04"),
    # EAP Identity Request
    (eap(code=0x01, identifier=0x56, length=5, type_=0x01,
         data=eap_identify()), "\x01\x56\x00\x05" "\x01"),
    # EAP Identity Response
    (eap(code=0x02, identifier=0x78, length=10, type_=0x01,
         data=eap_identify("hello")), "\x02\x78\x00\x0a" "\x01hello"),
    # EAP MD5 Challenge Request
    (eap(code=0x01, identifier=0x9a, length=19, type_=0x04,
         data=eap_md5_challenge("testchallenge")),
     "\x01\x9a\x00\x13" "\x04\x0dtestchallenge"),
    # EAP MD5 Challenge Response
    (eap(code=0x01, identifier=0xbc, length=18, type_=0x04,
         data=eap_md5_challenge("testresponse")),
     "\x01\xbc\x00\x12" "\x04\x0ctestresponse"),
    # EAP Unknown Request
    (eap(code=0x01, identifier=0xde, length=13, type_=0xaa,
         data="hogehoge"), "\x01\xde\x00\x0d" "\xaahogehoge"),
]


def test_eap():
    for (protocol, binary) in EAP_TEST_CASES:
        yield check_parse_eap, protocol, binary
        yield check_serialize_eap, protocol, binary


def check_parse_eap(p, b):
    pkt = packet.Packet(data=b, protocols=None, parse_cls=eap)
    pkt_eap = pkt.get_protocol(eap)

    eq_(pkt_eap, p)


def check_serialize_eap(p, b):
    pkt = packet.Packet()
    pkt.add_protocol(p)
    pkt.serialize()

    eq_(pkt.data, b)

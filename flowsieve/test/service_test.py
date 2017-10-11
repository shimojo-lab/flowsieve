from unittest import TestCase

from flowsieve.acl.service_acl import PROTO_DDP, PROTO_SCTP, \
    Service, TP_PROTO_TCP, TP_PROTO_UDP

from nose.tools import eq_, ok_


class UserSetTestCase(TestCase):
    def test_parse_invalid_format(self):
        eq_(Service.from_str("tcp/123/abc"), None)
        eq_(Service.from_str("icmp/456"), None)
        eq_(Service.from_str("udp/-10"), None)
        eq_(Service.from_str("udp/123456"), None)
        eq_(Service.from_str("udp/"), None)
        eq_(Service.from_str("udp//"), None)
        eq_(Service.from_str("/"), None)
        eq_(Service.from_str(""), None)
        eq_(Service.from_str("   "), None)
        eq_(Service.from_str("tcp/99999999"), None)
        eq_(Service.from_str("tcp/0"), None)
        eq_(Service.from_str("tcp/587a"), None)
        eq_(Service.from_str("udp22"), None)
        eq_(Service.from_str("udp/ 22"), None)
        eq_(Service.from_str("udp?22"), None)
        eq_(Service.from_str("tcp/0.5"), None)

    def test_parse_valid_format(self):
        eq_(Service.from_str("udp/53"), Service(TP_PROTO_UDP, 53))
        eq_(Service.from_str("tcp/443"), Service(TP_PROTO_TCP, 443))
        eq_(Service.from_str("tcp/http"), Service(TP_PROTO_TCP, 80))
        eq_(Service.from_str("udp/http"), Service(TP_PROTO_UDP, 80))
        eq_(Service.from_str("tcp/telnet"), Service(TP_PROTO_TCP, 23))
        eq_(Service.from_str("udp/27374"), Service(TP_PROTO_UDP, 27374))
        eq_(Service.from_str("tcp/22"), Service(TP_PROTO_TCP, 22))
        eq_(Service.from_str("udp/22"), Service(TP_PROTO_UDP, 22))
        eq_(Service.from_str("tcp/tfido"), Service(TP_PROTO_TCP, 60177))
        eq_(Service.from_str("tcp/fido"), Service(TP_PROTO_TCP, 60179))
        eq_(Service.from_str("tcp/60179"), Service(TP_PROTO_TCP, 60179))
        eq_(Service.from_str("tcp/5672"), Service(TP_PROTO_TCP, 5672))
        eq_(Service.from_str("udp/5672"), Service(TP_PROTO_UDP, 5672))
        eq_(Service.from_str("sctp/5672"), Service(PROTO_SCTP, 5672))
        eq_(Service.from_str("tcp/amqp"), Service(TP_PROTO_TCP, 5672))
        eq_(Service.from_str("udp/amqp"), Service(TP_PROTO_UDP, 5672))
        eq_(Service.from_str("sctp/amqp"), Service(PROTO_SCTP, 5672))
        eq_(Service.from_str("ddp/1"), Service(PROTO_DDP, 1))
        eq_(Service.from_str("ddp/zip"), Service(PROTO_DDP, 6))

    def test_eq_op(self):
        ok_(Service(TP_PROTO_TCP, 123) == Service(TP_PROTO_TCP, 123))
        ok_(Service(TP_PROTO_TCP, 123) != Service(TP_PROTO_UDP, 123))
        ok_(Service(TP_PROTO_TCP, 123) != Service(TP_PROTO_TCP, 789))

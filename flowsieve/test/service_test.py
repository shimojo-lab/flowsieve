from unittest import TestCase

from nose.tools import eq_, ok_

from flowsieve.acl.service_acl import Service, TP_PROTO_TCP, TP_PROTO_UDP


class UserSetTestCase(TestCase):
    def test_parse_invalid_format(self):
        eq_(Service.from_str("tcp/123/abc"), None)
        eq_(Service.from_str("icmp/456"), None)
        eq_(Service.from_str("tcp/http"), None)
        eq_(Service.from_str("udp/-10"), None)
        eq_(Service.from_str("udp/123456"), None)

    def test_parse_valid_format(self):
        eq_(Service.from_str("udp/53"), Service(TP_PROTO_UDP, 53))
        eq_(Service.from_str("tcp/443"), Service(TP_PROTO_TCP, 443))

    def test_eq_op(self):
        ok_(Service(TP_PROTO_TCP, 123) == Service(TP_PROTO_TCP, 123))
        ok_(Service(TP_PROTO_TCP, 123) != Service(TP_PROTO_UDP, 123))
        ok_(Service(TP_PROTO_TCP, 123) != Service(TP_PROTO_TCP, 789))

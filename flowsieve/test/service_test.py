from unittest import TestCase

from flowsieve.acl.service_acl import Service

from nose.tools import eq_, ok_


class UserSetTestCase(TestCase):
    def test_parse_invalid_format(self):
        eq_(Service.from_str("udp/"), None)
        eq_(Service.from_str("/"), None)
        eq_(Service.from_str(""), None)
        eq_(Service.from_str("   "), None)
        eq_(Service.from_str("tcp/587a"), None)
        eq_(Service.from_str("udp22"), None)

    def test_parse_valid_format(self):
        eq_(Service.from_str("udp/53"), Service("udp", 53))
        eq_(Service.from_str("tcp/443"), Service("tcp", 443))
        eq_(Service.from_str("tcp/http"), Service("tcp", 80))
        eq_(Service.from_str("udp/http"), Service("udp", 80))
        eq_(Service.from_str("tcp/telnet"), Service("tcp", 23))
        eq_(Service.from_str("udp/27374"), Service("udp", 27374))
        eq_(Service.from_str("tcp/22"), Service("tcp", 22))
        eq_(Service.from_str("udp/22"), Service("udp", 22))
        eq_(Service.from_str("tcp/60179"), Service("tcp", 60179))
        eq_(Service.from_str("tcp/5672"), Service("tcp", 5672))
        eq_(Service.from_str("udp/5672"), Service("udp", 5672))
        eq_(Service.from_str("tcp/amqp"), Service("tcp", 5672))
        eq_(Service.from_str("udp/amqp"), Service("udp", 5672))

    def test_eq_op(self):
        ok_(Service("tcp", 123) == Service("tcp", 123))
        ok_(Service("tcp", 123) != Service("udp", 123))
        ok_(Service("tcp", 123) != Service("tcp", 789))

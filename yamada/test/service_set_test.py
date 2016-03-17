from unittest import TestCase

from nose.tools import ok_

from yamada.acl.service_acl import Service
from yamada.acl.service_set import ServiceSet


class ServiceSetTestCase(TestCase):
    def setUp(self):
        self.http = Service.from_str("tcp/80")
        self.https = Service.from_str("tcp/443")
        self.dns = Service.from_str("udp/53")
        self.ssh = Service.from_str("tcp/22")
        self.dhcp = Service.from_str("udp/67")
        self.ftp = Service.from_str("tcp/21")

    def test_empty_set(self):
        ok_(self.http not in ServiceSet.empty())
        ok_(self.https not in ServiceSet.empty())
        ok_(self.dns not in ServiceSet.empty())
        ok_(self.ssh not in ServiceSet.empty())
        ok_(self.dhcp not in ServiceSet.empty())
        ok_(self.ftp not in ServiceSet.empty())

    def test_whole_set(self):
        ok_(self.http in ServiceSet.whole())
        ok_(self.https in ServiceSet.whole())
        ok_(self.dns in ServiceSet.whole())
        ok_(self.ssh in ServiceSet.whole())
        ok_(self.dhcp in ServiceSet.whole())
        ok_(self.ftp in ServiceSet.whole())

    def test_initializer(self):
        service_set = ServiceSet(services=[self.http, self.https])
        ok_(self.http in service_set)
        ok_(self.https in service_set)
        ok_(self.dns not in service_set)
        ok_(self.ssh not in service_set)
        ok_(self.dhcp not in service_set)
        ok_(self.ftp not in service_set)

    def test_add_op(self):
        service_set1 = ServiceSet(services=[self.http, self.https])
        service_set2 = ServiceSet(services=[self.ssh])
        service_set = service_set1 + service_set2

        ok_(self.http in service_set)
        ok_(self.https in service_set)
        ok_(self.dns not in service_set)
        ok_(self.ssh in service_set)
        ok_(self.dhcp not in service_set)
        ok_(self.ftp not in service_set)

    def test_sub_op(self):
        service_set1 = ServiceSet(services=[self.dns, self.dhcp, self.ftp])
        service_set2 = ServiceSet(services=[self.dns, self.ftp])
        service_set = service_set1 - service_set2

        ok_(self.http not in service_set)
        ok_(self.https not in service_set)
        ok_(self.dns not in service_set)
        ok_(self.ssh not in service_set)
        ok_(self.dhcp in service_set)
        ok_(self.ftp not in service_set)

    def test_and_op(self):
        service_set1 = ServiceSet(services=[self.dns, self.dhcp, self.ftp])
        service_set2 = ServiceSet(services=[self.dns, self.ftp])
        service_set = service_set1 & service_set2

        ok_(self.http not in service_set)
        ok_(self.https not in service_set)
        ok_(self.dns in service_set)
        ok_(self.ssh not in service_set)
        ok_(self.dhcp not in service_set)
        ok_(self.ftp in service_set)

    def test_complex_op(self):
        service_set1 = ServiceSet(services=[self.http, self.https])
        service_set2 = ServiceSet(services=[self.ssh, self.dns, self.dhcp])
        service_set3 = ServiceSet(services=[self.https, self.ssh])
        service_set = service_set1 + service_set2 - service_set3

        ok_(self.http in service_set)
        ok_(self.https not in service_set)
        ok_(self.dns in service_set)
        ok_(self.ssh not in service_set)
        ok_(self.dhcp in service_set)
        ok_(self.ftp not in service_set)

    def test_unary_pos_op(self):
        service_set = +ServiceSet(services=[self.http, self.https, self.ssh])

        ok_(self.http in service_set)
        ok_(self.https in service_set)
        ok_(self.dns not in service_set)
        ok_(self.ssh in service_set)
        ok_(self.dhcp not in service_set)
        ok_(self.ftp not in service_set)

    def test_unary_neg_op(self):
        service_set = -ServiceSet(services=[self.http, self.https, self.ssh])

        ok_(self.http not in service_set)
        ok_(self.https not in service_set)
        ok_(self.dns in service_set)
        ok_(self.ssh not in service_set)
        ok_(self.dhcp in service_set)
        ok_(self.ftp in service_set)

from unittest import TestCase

from nose.tools import ok_

from yamada.acl.user_acl import UserACL
from yamada.user_store import Role, User


class UserACLTestCase(TestCase):
    def setUp(self):
        self.role1 = Role("role1", {})
        self.role2 = Role("role2", {})

        self.user1 = User("user1", "", "role1", [])
        self.user1.role = self.role1

        self.user2 = User("user2", "", "role1", [])
        self.user2.role = self.role1

        self.user3 = User("user3", "", "role2", [])
        self.user3.role = self.role2

        self.user4 = User("user4", "", "role2", [])
        self.user4.role = self.role2

    def test_user_acl(self):
        self.user1_acl = UserACL()
        self.user1_acl.user = self.user1
        self.user1_acl.allowed_roles = [self.role2]
        self.user1_acl.denied_users = [self.user4]
        self.user1_acl.build_user_set()

        self.user2_acl = UserACL()
        self.user2_acl.user = self.user2
        self.user2_acl.default = "allow"
        self.user2_acl.build_user_set()

        self.user3_acl = UserACL()
        self.user3_acl.user = self.user3
        self.user3_acl.default = "allow"
        self.user3_acl.build_user_set()

        self.user4_acl = UserACL()
        self.user4_acl.user = self.user4
        self.user4_acl.default = "allow"
        self.user4_acl.build_user_set()

        ok_(not self.user1_acl.allows_packet(None, self.user2))
        ok_(self.user1_acl.allows_packet(None, self.user3))
        ok_(not self.user1_acl.allows_packet(None, self.user4))

        ok_(self.user2_acl.allows_packet(None, self.user1))
        ok_(self.user3_acl.allows_packet(None, self.user1))
        ok_(self.user4_acl.allows_packet(None, self.user1))

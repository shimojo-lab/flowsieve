from unittest import TestCase

from flowsieve.acl.user_acl import UserACL
from flowsieve.user_store import Role, User

from nose.tools import ok_


class UserACLTestCase(TestCase):
    def setUp(self):
        self.role1 = Role("role1", {})
        self.role2 = Role("role2", {})

        self.user1 = User("user1", "", "role1", {})
        self.user1.role = self.role1

        self.user2 = User("user2", "", "role1", {})
        self.user2.role = self.role1

        self.user3 = User("user3", "", "role1", {})
        self.user3.role = self.role1

        self.user4 = User("user4", "", "role2", {})
        self.user4.role = self.role2

    def test_default_default(self):
        user1_acl = UserACL(user=self.user1, role=self.user1.role)
        user1_acl.build_user_set()

        ok_(user1_acl.allows_packet(None, self.user2))
        ok_(user1_acl.allows_packet(None, self.user3))
        ok_(user1_acl.allows_packet(None, self.user4))

    def test_default_allow(self):
        user1_acl = UserACL(user=self.user1, role=self.user1.role,
                            default="allow")
        user1_acl.build_user_set()

        ok_(user1_acl.allows_packet(None, self.user2))
        ok_(user1_acl.allows_packet(None, self.user3))
        ok_(user1_acl.allows_packet(None, self.user4))

    def test_default_deny(self):
        user1_acl = UserACL(user=self.user1, role=self.user1.role,
                            default="deny", family=False)
        user1_acl.build_user_set()

        ok_(not user1_acl.allows_packet(None, self.user2))
        ok_(not user1_acl.allows_packet(None, self.user3))
        ok_(not user1_acl.allows_packet(None, self.user4))

    def test_allowed_roles(self):
        user1_acl = UserACL(user=self.user1, default="deny",
                            family=False, role=self.user1.role)
        user1_acl.allowed_roles = [self.role2]
        user1_acl.build_user_set()

        ok_(not user1_acl.allows_packet(None, self.user2))
        ok_(user1_acl.allows_packet(None, self.user4))

    def test_allowed_users(self):
        user1_acl = UserACL(user=self.user1, default="deny",
                            family=False, arole=self.user1.role)
        user1_acl.allowed_users = [self.user2]
        user1_acl.build_user_set()

        ok_(user1_acl.allows_packet(None, self.user2))
        ok_(not user1_acl.allows_packet(None, self.user3))

    def test_denied_roles(self):
        user1_acl = UserACL(user=self.user1, role=self.user1.role,
                            default="allow")
        user1_acl.denied_roles = [self.role2]
        user1_acl.build_user_set()

        ok_(user1_acl.allows_packet(None, self.user2))
        ok_(not user1_acl.allows_packet(None, self.user4))

    def test_denied_users(self):
        user1_acl = UserACL(user=self.user1, role=self.user1.role,
                            default="allow")
        user1_acl.denied_users = [self.user2]
        user1_acl.build_user_set()

        ok_(not user1_acl.allows_packet(None, self.user2))
        ok_(user1_acl.allows_packet(None, self.user3))

    def test_same_user(self):
        user1_acl = UserACL(user=self.user1, default="deny",
                            family=False, role=self.user1.role)
        user1_acl.build_user_set()

        ok_(user1_acl.allows_packet(None, self.user1))
        ok_(not user1_acl.allows_packet(None, self.user2))

    def test_intra_role_communication(self):
        allow_family_acl = UserACL(role=self.user1.role, default="deny")
        allow_family_acl.build_user_set()
        ok_(allow_family_acl.allows_packet(None, self.user2))
        ok_(not allow_family_acl.allows_packet(None, self.user4))

        deny_family_acl = UserACL(default="deny",
                                  role=self.user1.role, family=False)
        deny_family_acl.build_user_set()

        ok_(not deny_family_acl.allows_packet(None, self.user2))
        ok_(not deny_family_acl.allows_packet(None, self.user4))

    def test_invalid_default(self):
        user1_acl = UserACL(user=self.user1, role=self.user1.role,
                            default="deni")
        user1_acl.build_user_set()

        ok_(user1_acl.allows_packet(None, self.user1))
        ok_(user1_acl.allows_packet(None, self.user2))
        ok_(user1_acl.allows_packet(None, self.user3))
        ok_(user1_acl.allows_packet(None, self.user4))

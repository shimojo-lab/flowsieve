from unittest import TestCase

from nose.tools import ok_

from yamada.acl.user_acl import UserACL
from yamada.user_store import Role, User


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

    def test_default_allow(self):
        user1_acl = UserACL(user=self.user1, role=self.user1.role,
                            default="allow")
        user1_acl.build_user_set()

        ok_(user1_acl.allows_packet(None, self.user2))
        ok_(user1_acl.allows_packet(None, self.user3))
        ok_(user1_acl.allows_packet(None, self.user4))

    def test_default_deny(self):
        user1_acl = UserACL(user=self.user1, role=self.user1.role,
                            default="deny")
        user1_acl.build_user_set()

        ok_(not user1_acl.allows_packet(None, self.user2))
        ok_(not user1_acl.allows_packet(None, self.user3))
        ok_(not user1_acl.allows_packet(None, self.user4))

    def test_allowed_roles(self):
        user1_acl = UserACL(user=self.user1, role=self.user1.role)
        user1_acl.allowed_roles = [self.role2]
        user1_acl.build_user_set()

        ok_(not user1_acl.allows_packet(None, self.user2))
        ok_(user1_acl.allows_packet(None, self.user4))

    def test_allowed_users(self):
        user1_acl = UserACL(user=self.user1, role=self.user1.role)
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
        user1_acl = UserACL(user=self.user1, role=self.user1.role)
        user1_acl.build_user_set()

        ok_(user1_acl.allows_packet(None, self.user1))
        ok_(not user1_acl.allows_packet(None, self.user2))

    def test_public_user(self):
        user1_acl = UserACL(user=self.user1, role=self.user1.role, public=True)
        user1_acl.build_user_set()

        ok_(user1_acl.allows_packet(None, self.user2))
        ok_(user1_acl.allows_packet(None, self.user3))
        ok_(user1_acl.allows_packet(None, self.user4))

    def test_intra_role_communication(self):
        user1_acl = UserACL(user=self.user1, role=self.user1.role, family=True)
        user1_acl.build_user_set()

        ok_(user1_acl.allows_packet(None, self.user2))
        ok_(not user1_acl.allows_packet(None, self.user4))

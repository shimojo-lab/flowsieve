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

        self.user3 = User("user3", "", "role1", [])
        self.user3.role = self.role1

        self.user4 = User("user4", "", "role2", [])
        self.user4.role = self.role2

        self.user5 = User("user5", "", "role2", [])
        self.user5.role = self.role2

        self.user6 = User("user6", "", "role2", [])
        self.user6.role = self.role2

    def test_user_acl(self):
        user1_acl = UserACL(user=self.user1)
        user1_acl.allowed_roles = [self.role2]
        user1_acl.denied_users = [self.user4]
        user1_acl.build_user_set()

        user2_acl = UserACL(user=self.user2, default="allow")
        user2_acl.build_user_set()

        user3_acl = UserACL(user=self.user3, default="allow")
        user3_acl.build_user_set()

        user4_acl = UserACL(user=self.user4, default="allow")
        user4_acl.build_user_set()

        user5_acl = UserACL(user=self.user4, default="allow")
        user5_acl.build_user_set()

        user4_acl = UserACL(user=self.user4, default="allow")
        user4_acl.build_user_set()

        ok_(not user1_acl.allows_packet(None, self.user2))
        ok_(not user1_acl.allows_packet(None, self.user3))
        ok_(not user1_acl.allows_packet(None, self.user4))

        ok_(user2_acl.allows_packet(None, self.user1))
        ok_(user3_acl.allows_packet(None, self.user1))
        ok_(user4_acl.allows_packet(None, self.user1))

    def test_same_user(self):
        user1_acl = UserACL(user=self.user1)
        user1_acl.build_user_set()

        ok_(user1_acl.allows_packet(None, self.user1))
        ok_(not user1_acl.allows_packet(None, self.user2))

    def test_public_user(self):
        user1_acl = UserACL(user=self.user1, public=True)
        user1_acl.build_user_set()

        user2_acl = UserACL(user=self.user2, default="allow")
        user2_acl.build_user_set()

        user3_acl = UserACL(user=self.user3, default="deny")
        user3_acl.build_user_set()

        ok_(user1_acl.allows_packet(None, self.user2))
        ok_(user1_acl.allows_packet(None, self.user3))

        ok_(user2_acl.allows_packet(None, self.user1))
        ok_(not user3_acl.allows_packet(None, self.user1))

    def test_intra_role_communication(self):
        user1_acl = UserACL(user=self.user1, family=True)
        user1_acl.build_user_set()

        user2_acl = UserACL(user=self.user2)
        user2_acl.build_user_set()

        ok_(not user1_acl.allows_packet(None, self.user2))
        ok_(not user2_acl.allows_packet(None, self.user1))

    def test_default(self):
        user1_acl = UserACL(user=self.user1, default="allow")
        user1_acl.build_user_set()

        user2_acl = UserACL(user=self.user2, default="deny")
        user2_acl.build_user_set()

        ok_(user1_acl.allows_packet(None, self.user2))
        ok_(not user2_acl.allows_packet(None, self.user1))

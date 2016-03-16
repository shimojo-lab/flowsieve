from unittest import TestCase

from nose.tools import ok_

from yamada.user_store import UserStore


class AccessControlTestCase(TestCase):
    def setUp(self):
        self.user_store = UserStore("yamada/test/test_access_control.yml")
        self.user1 = self.user_store.get_user("user1")
        self.user1_family = self.user_store.get_user("user1_family")
        self.user2 = self.user_store.get_user("user2")
        self.user3 = self.user_store.get_user("user3")
        self.public_user = self.user_store.get_user("public_user")
        self.family_user1 = self.user_store.get_user("family_user1")
        self.family_user2 = self.user_store.get_user("family_user2")
        self.allow_role1_user = self.user_store.get_user("allow_role1_user")
        self.default_allow_user = self.user_store.get_user("default"
                                                           "_allow_user")
        self.default_deny_user = self.user_store.get_user("default"
                                                          "_deny_user")
        self.inherit_user = self.user_store.get_user("inherit_user")
        self.not_inherit_user = self.user_store.get_user("not_inherit_user")

    def test_same_user(self):
        ok_(self.user1.acls["UserACL"].allows_packet(None, self.user1))
        ok_(self.user2.acls["UserACL"].allows_packet(None, self.user2))
        ok_(self.user3.acls["UserACL"].allows_packet(None, self.user3))
        ok_(self.public_user.acls["UserACL"].allows_packet(
            None, self.public_user))
        ok_(self.family_user1.acls["UserACL"].allows_packet(
            None, self.family_user1))
        ok_(self.family_user2.acls["UserACL"].allows_packet(
            None, self.family_user2))

    def test_public_user(self):
        ok_(self.public_user.acls["UserACL"].allows_packet(None, self.user1))
        ok_(self.public_user.acls["UserACL"].allows_packet(None, self.user2))
        ok_(self.public_user.acls["UserACL"].allows_packet(None, self.user3))
        ok_(self.public_user.acls["UserACL"].allows_packet(
            None, self.public_user))
        ok_(self.public_user.acls["UserACL"].allows_packet(
            None, self.family_user1))
        ok_(self.public_user.acls["UserACL"].allows_packet(
            None, self.family_user2))

    def test_intra_role_communication(self):
        ok_(not self.user1_family.acls["UserACL"].allows_packet(
            None, self.user1))
        ok_(self.family_user1.acls["UserACL"].allows_packet(
            None, self.family_user2))
        ok_(self.family_user2.acls["UserACL"].allows_packet(
            None, self.family_user1))

    def test_acl(self):
        ok_(self.user1.acls["UserACL"].allows_packet(
            None, self.user2))
        ok_(self.user1.acls["UserACL"].allows_packet(
            None, self.user3))
        ok_(self.user2.acls["UserACL"].allows_packet(
            None, self.user1))
        ok_(self.user3.acls["UserACL"].allows_packet(
            None, self.user1))
        ok_(not self.user2.acls["UserACL"].allows_packet(
            None, self.user3))
        ok_(not self.user3.acls["UserACL"].allows_packet(
            None, self.user2))

    def test_allowed_roles(self):
        ok_(self.user1.acls["UserACL"].allows_packet(
            None, self.allow_role1_user))
        ok_(self.allow_role1_user.acls["UserACL"].allows_packet(
            None, self.user1))
        ok_(not self.user2.acls["UserACL"].allows_packet(
            None, self.allow_role1_user))
        ok_(not self.allow_role1_user.acls["UserACL"].allows_packet(
            None, self.user2))

    def test_default(self):
        ok_(self.default_allow_user.acls["UserACL"].allows_packet(
            None, self.user1))
        ok_(not self.default_deny_user.acls["UserACL"].allows_packet(
            None, self.user1))

    def test_inherit(self):
        ok_(self.inherit_user.acls["UserACL"].allows_packet(
            None, self.user1))
        ok_(self.not_inherit_user.acls["UserACL"].allows_packet(
            None, self.user1))
        ok_(not self.inherit_user.acls["UserACL"].allows_packet(
            None, self.default_allow_user))
        ok_(self.not_inherit_user.acls["UserACL"].allows_packet(
            None, self.default_allow_user))

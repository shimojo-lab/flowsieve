from unittest import TestCase

from nose.tools import ok_

from yamada.user_store import UserStore


class AccessControlTestCase(TestCase):
    def setUp(self):
        self.user_store = UserStore("conf/test_access_control.yml")
        self.user1 = self.user_store.get_user("user1")
        self.user1_family = self.user_store.get_user("user1_family")
        self.user2 = self.user_store.get_user("user2")
        self.user3 = self.user_store.get_user("user3")
        self.public_user = self.user_store.get_user("public_user")
        self.family_user1 = self.user_store.get_user("family_user1")
        self.family_user2 = self.user_store.get_user("family_user2")

    def test_same_user(self):
        ok_(self.user1.can_access_user(self.user1))
        ok_(self.user2.can_access_user(self.user2))
        ok_(self.user3.can_access_user(self.user3))
        ok_(self.public_user.can_access_user(self.public_user))
        ok_(self.family_user1.can_access_user(self.family_user1))
        ok_(self.family_user2.can_access_user(self.family_user2))

    def test_public_user(self):
        ok_(self.user1.can_access_user(self.public_user))
        ok_(self.user2.can_access_user(self.public_user))
        ok_(self.user3.can_access_user(self.public_user))
        ok_(self.public_user.can_access_user(self.public_user))
        ok_(self.family_user1.can_access_user(self.public_user))
        ok_(self.family_user2.can_access_user(self.public_user))

    def test_intra_role_communication(self):
        ok_(not self.user1.can_access_user(self.user1_family))
        ok_(self.family_user1.can_access_user(self.family_user2))
        ok_(self.family_user2.can_access_user(self.family_user1))

    def test_acl(self):
        ok_(self.user1.can_access_user(self.user2))
        ok_(self.user1.can_access_user(self.user3))
        ok_(self.user2.can_access_user(self.user1))
        ok_(self.user3.can_access_user(self.user1))
        ok_(not self.user2.can_access_user(self.user3))
        ok_(not self.user3.can_access_user(self.user2))
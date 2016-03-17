from unittest import TestCase

from nose.tools import ok_

from yamada.acl.user_set import UserSet
from yamada.user_store import Role, User


class UserSetTestCase(TestCase):
    def setUp(self):
        self.role1 = Role("role1", {})
        self.role2 = Role("role2", {})
        self.role3 = Role("role3", {})

        self.user1 = User("user1", "", "role1", {})
        self.user1.role = self.role1
        self.user2 = User("user2", "", "role1", {})
        self.user2.role = self.role1
        self.user3 = User("user3", "", "role2", {})
        self.user3.role = self.role2
        self.user4 = User("user4", "", "role2", {})
        self.user4.role = self.role2
        self.user5 = User("user5", "", "role3", {})
        self.user5.role = self.role3
        self.user6 = User("user6", "", "role3", {})
        self.user6.role = self.role3

    def test_empty_set(self):
        ok_(self.user1 not in UserSet.empty())
        ok_(self.user2 not in UserSet.empty())
        ok_(self.user3 not in UserSet.empty())
        ok_(self.user4 not in UserSet.empty())
        ok_(self.user5 not in UserSet.empty())
        ok_(self.user6 not in UserSet.empty())

    def test_whole_set(self):
        ok_(self.user1 in UserSet.whole())
        ok_(self.user2 in UserSet.whole())
        ok_(self.user3 in UserSet.whole())
        ok_(self.user4 in UserSet.whole())
        ok_(self.user5 in UserSet.whole())
        ok_(self.user6 in UserSet.whole())

    def test_users_initializer(self):
        user_set = UserSet(users=[self.user1, self.user2, self.user3])
        ok_(self.user1 in user_set)
        ok_(self.user2 in user_set)
        ok_(self.user3 in user_set)
        ok_(self.user4 not in user_set)
        ok_(self.user5 not in user_set)
        ok_(self.user6 not in user_set)

    def test_roles_initializer(self):
        user_set = UserSet(roles=[self.role2, self.role3])
        ok_(self.user1 not in user_set)
        ok_(self.user2 not in user_set)
        ok_(self.user3 in user_set)
        ok_(self.user4 in user_set)
        ok_(self.user5 in user_set)
        ok_(self.user6 in user_set)

    def test_users_roles_initializer(self):
        user_set = UserSet(users=[self.user1], roles=[self.role2, self.role3])
        ok_(self.user1 in user_set)
        ok_(self.user2 not in user_set)
        ok_(self.user3 in user_set)
        ok_(self.user4 in user_set)
        ok_(self.user5 in user_set)
        ok_(self.user6 in user_set)

    def test_add_op(self):
        user_set1 = UserSet(users=[self.user1, self.user3, self.user5])
        user_set2 = UserSet(roles=[self.role1])
        user_set3 = user_set1 + user_set2

        ok_(self.user1 in user_set3)
        ok_(self.user2 in user_set3)
        ok_(self.user3 in user_set3)
        ok_(self.user4 not in user_set3)
        ok_(self.user5 in user_set3)
        ok_(self.user6 not in user_set3)

    def test_sub_op(self):
        user_set1 = UserSet(roles=[self.role1, self.role2])
        user_set2 = UserSet(users=[self.user1, self.user3])
        user_set3 = user_set1 - user_set2

        ok_(self.user1 not in user_set3)
        ok_(self.user2 in user_set3)
        ok_(self.user3 not in user_set3)
        ok_(self.user4 in user_set3)
        ok_(self.user5 not in user_set3)
        ok_(self.user6 not in user_set3)

    def test_and_op(self):
        user_set1 = UserSet(roles=[self.role1, self.role2])
        user_set2 = UserSet(users=[self.user1, self.user3])
        user_set3 = user_set1 & user_set2

        ok_(self.user1 in user_set3)
        ok_(self.user2 not in user_set3)
        ok_(self.user3 in user_set3)
        ok_(self.user4 not in user_set3)
        ok_(self.user5 not in user_set3)
        ok_(self.user6 not in user_set3)

    def test_complex_op(self):
        user_set1 = UserSet(roles=[self.role1, self.role2])
        user_set2 = UserSet(users=[self.user5])
        user_set3 = UserSet(users=[self.user6])
        user_set4 = user_set1 + user_set2 - user_set2 + user_set3

        ok_(self.user1 in user_set4)
        ok_(self.user2 in user_set4)
        ok_(self.user3 in user_set4)
        ok_(self.user4 in user_set4)
        ok_(self.user5 not in user_set4)
        ok_(self.user6 in user_set4)

    def test_unary_pos_op(self):
        user_set = +UserSet(users=[self.user1, self.user3], roles=[self.role3])

        ok_(self.user1 in user_set)
        ok_(self.user2 not in user_set)
        ok_(self.user3 in user_set)
        ok_(self.user4 not in user_set)
        ok_(self.user5 in user_set)
        ok_(self.user6 in user_set)

    def test_unary_neg_op(self):
        user_set = -UserSet(users=[self.user1, self.user3], roles=[self.role3])

        ok_(self.user1 not in user_set)
        ok_(self.user2 in user_set)
        ok_(self.user3 not in user_set)
        ok_(self.user4 in user_set)
        ok_(self.user5 not in user_set)
        ok_(self.user6 not in user_set)

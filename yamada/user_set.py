from yamada.user_store import Role, User


class UserSet(object):
    """Represents a set of users"""
    def __init__(self, users=[], roles=[], predicate=lambda u: False):
        super(UserSet, self).__init__()

        assert isinstance(users, list) or isinstance(users, set)
        assert isinstance(roles, list) or isinstance(roles, set)
        assert hasattr(predicate, "__call__")

        for user in users:
            assert isinstance(user, User)
        for role in roles:
            assert isinstance(role, Role)

        users = set(users)
        roles = set(roles)

        def user_pred(u):
            return any(map(lambda v: u == v, users))

        def role_pred(u):
            return any(map(lambda r: u.role == r, roles))

        self.predicate = lambda u: user_pred(u) or role_pred(u) or predicate(u)

    def __contains__(self, user):
        """Check if user is contained in this set"""
        return self.predicate(user)

    def __add__(self, other):
        """Compute union set"""
        return UserSet(predicate=lambda u: u in self or u in other)

    union = __add__

    def __sub__(self, other):
        """Compute difference set"""
        return UserSet(predicate=lambda u: u in self and u not in other)

    difference = __sub__

    def __and__(self, other):
        """Compute intersection set"""
        return UserSet(predicate=lambda u: u in self and u in other)

    intersection = __and__

    def __pos__(self):
        return UserSet(predicate=lambda u: u in self)

    def __neg__(self):
        """Compute complementary set"""
        return UserSet(predicate=lambda u: u not in self)

WHOLE_USER_SET = UserSet(predicate=lambda u: True)

EMPTY_USER_SET = UserSet(predicate=lambda u: False)

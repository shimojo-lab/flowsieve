from yamada.acl.base_set import BaseSet


class UserSet(BaseSet):
    """Represents a set of users"""
    def __init__(self, users=[], roles=[], predicate=lambda u: False):
        assert isinstance(users, list) or isinstance(users, set)
        assert isinstance(roles, list) or isinstance(roles, set)

        super(UserSet, self).__init__(
            lambda u: any([u == v for v in users]) or
            any([u.role == r for r in roles]) or predicate(u)
        )

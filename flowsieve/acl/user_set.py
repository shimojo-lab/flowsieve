from yamada.acl.base_set import BaseSet


class UserSet(BaseSet):
    """Represents a set of users"""
    def __init__(self, users=[], roles=[], predicate=lambda u: False):
        assert isinstance(users, list) or isinstance(users, set)
        assert isinstance(roles, list) or isinstance(roles, set)

        users = set(users)
        roles = set(roles)

        super(UserSet, self).__init__(
            lambda u: u in users or u.role in roles or predicate(u)
        )

import logging


class BaseACL(object):
    def __init__(self, **kwargs):
        super(BaseACL, self).__init__()
        # Role object if this ACL is associated to a role
        self.role = kwargs.get("role")
        # User object if this ACL is associated to an user
        self.user = kwargs.get("user")
        # Parent ACL object (e.g. parent of an user ACL is a role ACL)
        self.parent = kwargs.get("parent")

        self._logger = logging.getLogger(self.__class__.__name__)

    @classmethod
    def from_dict(cls, item):
        assert isinstance(item, dict)

        return cls(**item)

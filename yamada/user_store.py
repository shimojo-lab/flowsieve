import logging

from yamada.user_set import EMPTY_USER_SET, UserSet, WHOLE_USER_SET

from yaml import YAMLError, load


class UserStore(object):
    DEFAULT_USER_ROLE_FILE = "conf/user_store.yml"

    def __init__(self, file_name=None):
        super(UserStore, self).__init__()
        if file_name is None:
            file_name = UserStore.DEFAULT_USER_ROLE_FILE
        self.user_role_file = file_name
        self.users = {}
        self.roles = {}
        self._logger = logging.getLogger(self.__class__.__name__)

        self._read_definition_file()

    def get_user(self, user_name):
        assert isinstance(user_name, basestring)

        return self.users.get(user_name)

    def get_role(self, role_name):
        assert isinstance(role_name, basestring)

        return self.roles.get(role_name)

    def del_user(self, user_name):
        assert isinstance(user_name, basestring)

        del self.users[user_name]

    def del_role(self, role_name):
        assert isinstance(role_name, basestring)

        del self.roles[role_name]

    def _read_definition_file(self):
        try:
            data = load(file(self.user_role_file))
        except IOError:
            self._logger.error("Could not open %s", self.user_role_file)
            return
        except YAMLError:
            self._logger.warning("Error while parsing %s",
                                 self.user_role_file)
            return

        if "roles" in data:
            self._logger.info("Reading role data")
            self._store_role_data(data["roles"])
        if "users" in data:
            self._logger.info("Reading user data")
            self._store_user_data(data["users"])

        self._load_relations()

    def _store_user_data(self, items):
        for item in items:
            user = User.from_dict(item)

            if user is None:
                continue

            if user.name in self.users:
                self._logger.warning("Duplicate user name %s", user.name)
                continue

            self.users[user.name] = user

    def _store_role_data(self, items):
        for item in items:
            role = Role.from_dict(item)

            if role is None:
                continue

            if role.name in self.roles:
                self._logger.warning("Duplicate role name %s", role.name)
                continue

            self.roles[role.name] = role

    def _load_relations(self):
        """Load relations between models"""
        for role in self.roles.values():
            role.load_relations(self)
        for user in self.users.values():
            user.load_relations(self)


class Role(object):
    def __init__(self, name, acl):
        super(Role, self).__init__()
        self.name = name
        self.acl = acl
        self._logger = logging.getLogger(self.__class__.__name__)

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.name == other.name

    def load_relations(self, user_store):
        self.acl.role = self
        self.acl.load_relations(user_store)

    def allows_user(self, other):
        assert isinstance(other, User)

        return other in self.user_set

    @classmethod
    def _validate_role_keys(cls, item):
        return "name" in item

    @classmethod
    def from_dict(cls, item):
        assert isinstance(item, dict)

        if not cls._validate_role_keys(item):
            return None

        name = item["name"]
        acl = ACL.from_dict(item)

        return Role(name, acl)

    def __repr__(self):
        return "<Role name=\"{0}\" acl={1}>".format(self.name, self.acl)


class User(object):
    def __init__(self, name, password, role_name, acl):
        super(User, self).__init__()
        self.name = name
        self.password = password
        self.role_name = role_name
        self.acl = acl
        self.role = None
        self._logger = logging.getLogger(self.__class__.__name__)

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.name == other.name

    def allows_user(self, other):
        return self.acl.allows_user(other)

    def load_relations(self, user_store):
        role = user_store.get_role(self.role_name)
        if role is None:
            self._logger.warning("Unknown role %s for user %s",
                                 self.role_name, self.name)
            user_store.del_user(self.name)

        self.role = role

        self.acl.user = self
        self.acl.parent = self.role.acl
        self.acl.load_relations(user_store)

    @classmethod
    def _validate_user_keys(cls, item):
        return "name" in item and "password" in item and "role" in item

    @classmethod
    def from_dict(cls, item):
        assert isinstance(item, dict)

        if not cls._validate_user_keys(item):
            return None

        name = item["name"]
        password = item["password"]
        role_name = item["role"]
        acl = ACL.from_dict(item)

        return User(name, password, role_name, acl)

    def __repr__(self):
        return "<User name=\"{0}\" role=\"{1}\">".format(
            self.name, self.role_name
        )


class ACL(object):
    def __init__(self, **kwargs):
        super(ACL, self).__init__()
        self.allowed_user_names = kwargs.get("allowed_users", [])
        self.allowed_users = []
        self.allowed_role_names = kwargs.get("allowed_roles", [])
        self.allowed_roles = []
        self.is_family = kwargs.get("family", False)
        self.is_public = kwargs.get("public", False)

        # Role object if this ACL is associated to a role
        self.role = kwargs.get("role")
        # User object if this ACL is associated to an user
        self.user = kwargs.get("user")
        # Parent ACL object (e.g. parent of an user ACL is a role ACL)
        self.parent = kwargs.get("parent")

        self.user_set = EMPTY_USER_SET
        self._logger = logging.getLogger(self.__class__.__name__)

    def load_relations(self, user_store):
        for user_name in self.allowed_user_names:
            user = user_store.get_user(user_name)
            if user is None:
                self._logger.warning("Unknwon user %s in section"
                                     " allowed_users of an ACL", user_name)
                continue

            self.allowed_users.append(user)

        for role_name in self.allowed_role_names:
            role = user_store.get_role(role_name)
            if role is None:
                self._logger.warning("Unknown role %s in section"
                                     " allowed_roles of an ACL", role_name)
                continue
            self.allowed_roles.append(role)

        self.build_user_set()

    def build_user_set(self):
        self.user_set = EMPTY_USER_SET

        if self.parent is not None:
            self.parent.build_user_set()
            self.user_set = self.parent.user_set

        if self.user is not None:
            self.user_set += UserSet(users=[self.user])

        if self.is_family and self.role is not None:
            self.user_set += UserSet(roles=[self.role])

        if self.is_public:
            self.user_set = WHOLE_USER_SET

        self.user_set += UserSet(users=self.allowed_users)
        self.user_set += UserSet(roles=self.allowed_roles)

    def allows_user(self, other):
        assert isinstance(other, User)

        return other in self.user_set

    @classmethod
    def from_dict(cls, item):
        assert isinstance(item, dict)

        return ACL(**item)

    def __repr__(self):
        repr_family = ""
        if self.is_family:
            repr_family = " family"
        repr_public = ""
        if self.is_public:
            repr_public = " public"

        return "<ACL{0}{1} allowed_users={2}>".format(
            repr_family, repr_public, self.allowed_user_names
        )

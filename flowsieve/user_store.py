import logging

from flowsieve.acl.service_acl import ServiceACL
from flowsieve.acl.user_acl import UserACL

from yaml import YAMLError, load

ACL_CLASSES = [UserACL, ServiceACL]


class UserStore(object):
    DEFAULT_USER_ROLE_FILE = "conf/user_store.yml"

    _instances = {}

    @classmethod
    def get_instance(cls, file_name=DEFAULT_USER_ROLE_FILE):
        if file_name not in cls._instances:
            cls._instances[file_name] = cls(file_name)

        return cls._instances[file_name]

    def __init__(self, file_name=DEFAULT_USER_ROLE_FILE):
        super(UserStore, self).__init__()
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

        self.users.pop(user_name)

    def del_role(self, role_name):
        assert isinstance(role_name, basestring)

        self.roles.pop(role_name)

    def _read_definition_file(self):
        try:
            data = load(file(self.user_role_file))
        except IOError:
            self._logger.error("Could not open %s", self.user_role_file)
            return
        except YAMLError:
            self._logger.error("Error while parsing %s", self.user_role_file)
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
        for role in self.roles.itervalues():
            role.load_relations(self)
        for user in self.users.itervalues():
            user.load_relations(self)


class Role(object):
    def __init__(self, name, acls):
        super(Role, self).__init__()
        self.name = name
        self.acls = acls
        self._logger = logging.getLogger(self.__class__.__name__)

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.name == other.name

    def __hash__(self):
        return hash(self.name)

    def load_relations(self, user_store):
        for acl in self.acls.itervalues():
            acl.role = self
            acl.load_relations(user_store)

    @classmethod
    def _validate_role_keys(cls, item):
        return "name" in item

    @classmethod
    def from_dict(cls, item):
        assert isinstance(item, dict)

        if not cls._validate_role_keys(item):
            logger = logging.getLogger(cls.__name__)
            logger.warning("Skipping role since required key is missing")
            return None

        name = item["name"]
        acls = dict([(c.__name__, c.from_dict(item)) for c in ACL_CLASSES])

        return Role(name, acls)

    def __repr__(self):
        return "<Role name=\"{0}\" acl={1}>".format(self.name, self.acl)


class User(object):
    def __init__(self, name, password, role_name, acls):
        super(User, self).__init__()
        self.name = name
        self.password = password
        self.role_name = role_name
        self.acls = acls
        self.role = None
        self._logger = logging.getLogger(self.__class__.__name__)

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.name == other.name

    def __hash__(self):
        return hash(self.name)

    def load_relations(self, user_store):
        role = user_store.get_role(self.role_name)
        if role is None:
            self._logger.warning("Unknown role %s for user %s",
                                 self.role_name, self.name)
            user_store.del_user(self.name)

        self.role = role

        for name, acl in self.acls.iteritems():
            acl.user = self
            acl.parent = self.role.acls.get(name)
            acl.load_relations(user_store)

    @classmethod
    def _validate_user_keys(cls, item):
        return "name" in item and "password" in item and "role" in item

    @classmethod
    def from_dict(cls, item):
        assert isinstance(item, dict)

        if not cls._validate_user_keys(item):
            logger = logging.getLogger(cls.__name__)
            logger.warning("Skipping user since required key is missing")
            return None

        name = item["name"]
        password = item["password"]
        role_name = item["role"]
        acls = dict([(c.__name__, c.from_dict(item)) for c in ACL_CLASSES])

        return User(name, password, role_name, acls)

    def __repr__(self):
        return "<User name=\"{0}\" role=\"{1}\">".format(
            self.name, self.role_name
        )

import logging

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
        return self.users.get(user_name)

    def authorize_access(self, user1, user2):
        if user1 is None or user2 is None:
            return False

        # If any of the two is public, grant access
        if user1.role.acl.is_public or user2.role.acl.is_public:
            return True

        # Allow intra-role communication if role is a family
        if user1.role == user2.role:
            if user1.role.acl.is_family:
                return True

        # Check for both directions
        check1 = user2 in user1.role.acl.allowed_users
        check2 = user1 in user2.role.acl.allowed_users

        return check1 and check2

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

    def _store_user_data(self, users):
        for user in users:
            if not self._validate_user_keys(user):
                continue

            name = user["name"]
            password = user["password"]
            role_name = user["role"]
            u = User(name, password, role_name)

            if name in self.users:
                self._logger.warning("Duplicate user name %s", name)
                continue
            self.users[name] = u

    def _store_role_data(self, roles):
        for role in roles:
            if not self._validate_role_keys(role):
                continue

            name = role["name"]
            acl = ACL(allowed_users=role.get("allowed_users", []),
                      is_public=role.get("public", False),
                      is_family=role.get("family", False))

            r = Role(name, acl)
            if name in self.roles:
                self._logger.warning("Duplicate role name %s", name)
                continue
            self.roles[name] = r

    def _validate_user_keys(self, user):
        return "name" in user and "password" in user and "role" in user

    def _validate_role_keys(self, role):
        return "name" in role

    def _load_relations(self):
        """Load relations between models"""
        for user in self.users.values():
            role = self.roles.get(user.role_name)
            if role is None:
                self._logger.warning("Unknown role %s for user %s",
                                     user.role_name, user.name)
                del self.users[user.name]

            user.role = role

        for role in self.roles.values():
            for user_name in role.acl.allowed_user_names:
                user = self.users.get(user_name)
                if user is None:
                    self._logger.warning("Unknwon user %s in section"
                                         " allowed_users of role %s",
                                         user_name, role.name)
                    continue

                role.acl.allowed_users.append(user)


class Role(object):
    def __init__(self, name, acl):
        super(Role, self).__init__()
        self.name = name
        self.acl = acl

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.name == other.name


class User(object):
    def __init__(self, name, password, role_name):
        super(User, self).__init__()
        self.name = name
        self.password = password
        self.role_name = role_name
        self.role = None

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.name == other.name


class ACL(object):
    def __init__(self, **kwargs):
        super(ACL, self).__init__()
        self.allowed_user_names = kwargs.get("allowed_users", [])
        self.allowed_users = []
        self.is_family = kwargs.get("is_family", False)
        self.is_public = kwargs.get("is_public", False)

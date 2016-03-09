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
        self.resources = {}
        self._logger = logging.getLogger(self.__class__.__name__)

        self._read_definition_file()

    def get_user(self, user_name):
        return self.users.get(user_name)

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

        self._check_inconsistency()

    def _store_user_data(self, users):
        for user in users:
            if not self._validate_user_keys(user):
                continue

            name = user["name"]
            password = user["password"]
            role = user["role"]
            u = User(name, password, role)

            if name in self.users:
                self._logger.warning("Duplicate user name %s", name)
                continue
            self.users[name] = u

    def _store_role_data(self, roles):
        for role in roles:
            if not self._validate_role_keys(role):
                continue

            name = role["name"]

            is_public = role.get("public", False)
            allowed_users = role.get("allowed_users")
            acl = ACL(is_public, allowed_users)

            r = Role(name, acl)
            if name in self.roles:
                self._logger.warning("Duplicate role name %s", name)
                continue
            self.roles[name] = r

    def _check_inconsistency(self):
        # TODO Check incosistency in models and relations.
        pass

    def _validate_user_keys(self, user):
        return "name" in user and "password" in user and "role" in user

    def _validate_role_keys(self, role):
        return "name" in role


class Role(object):
    def __init__(self, name, acl):
        super(Role, self).__init__()
        self.name = name
        self.acl = acl


class User(object):
    def __init__(self, name, password, role):
        super(User, self).__init__()
        self.name = name
        self.password = password
        self.role = role


class ACL(object):
    def __init__(self, is_public=False, allowed_users=None):
        super(ACL, self).__init__()
        self.is_public = is_public
        if allowed_users is None:
            self.allowed_users = []
        else:
            self.allowed_users = allowed_users

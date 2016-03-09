import logging

from netaddr import AddrFormatError, EUI, IPAddress

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

        if "resources" in data:
            self._logger.info("Reading resource data")
            self._store_resource_data(data["resources"])
        if "roles" in data:
            self._logger.info("Reading role data")
            self._store_role_data(data["roles"])
        if "users" in data:
            self._logger.info("Reading user data")
            self._store_user_data(data["users"])

    def _store_user_data(self, users):
        for user in users:
            if not self._validate_user_keys(user):
                continue

            name = user["name"]
            password = user["password"]
            role = user["role"]
            u = User(name, password, role)

            if role not in self.roles:
                self._logger.warning("Unknown role %s for user %s",
                                     role, name)
                continue
            if name in self.users:
                self._logger.warning("Duplicate user name %s", name)
                continue
            self.users[name] = u

    def _store_role_data(self, roles):
        for role in roles:
            if not self._validate_role_keys(role):
                continue

            name = role["name"]
            allowed_resources = []
            for resource in role["allowed_resources"]:
                if resource not in self.resources:
                    self._logger.warning("Unknown resource %s for role %s",
                                         resource, role)
                    continue
                allowed_resources += resource

            r = Role(name, allowed_resources)
            if name in self.roles:
                self._logger.warning("Duplicate role name %s", name)
                continue
            self.roles[name] = r

    def _store_resource_data(self, resources):
        for resource in resources:
            if not self._validate_resource_keys(resource):
                continue

            name = resource["name"]
            mac = None
            ip = None

            if "mac" in resource:
                try:
                    mac = EUI(resource["mac"])
                except AddrFormatError:
                    self._logger.warning("Malformed MAC address %s",
                                         resource["mac"])
            if "ip" in resource:
                try:
                    ip = IPAddress(resource["ip"])
                except AddrFormatError:
                    self._logger.warning("Malformed IP address %s",
                                         resource["ip"])

            r = Resource(name, mac, ip)

            if name in self.resources:
                self._logger.warning("Duplicate resource name %s", name)
                continue
            self.resources[name] = r

    def _validate_user_keys(self, user):
        return "name" in user and "password" in user and "role" in user

    def _validate_role_keys(self, role):
        return "name" in role

    def _validate_resource_keys(self, resource):
        if "name" not in resource:
            return False

        return "ip" in resource or "mac" in resource


class Resource(object):
    def __init__(self, name, mac=None, ip=None):
        super(Resource, self).__init__()
        self.name = name
        self.mac = mac
        self.ip = ip


class Role(object):
    def __init__(self, name, allowed_resources):
        super(Role, self).__init__()
        self.name = name
        self.allowed_resources = allowed_resources


class User(object):
    def __init__(self, name, password, role):
        super(User, self).__init__()
        self.name = name
        self.password = password
        self.role = role

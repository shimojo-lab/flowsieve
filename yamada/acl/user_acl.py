from ryu.lib.packet import ethernet

from yamada.acl.acl_result import ACLResult, PacketMatch
from yamada.acl.base_acl import BaseACL
from yamada.user_set import EMPTY_USER_SET, UserSet, WHOLE_USER_SET


class UserACL(BaseACL):
    def __init__(self, **kwargs):
        super(UserACL, self).__init__(**kwargs)
        self.allowed_user_names = kwargs.get("allowed_users", [])
        self.allowed_users = []
        self.allowed_role_names = kwargs.get("allowed_roles", [])
        self.allowed_roles = []
        self.is_family = kwargs.get("family", False)
        self.is_public = kwargs.get("public", False)
        self.default = kwargs.get("default", "")

        self.user_set = EMPTY_USER_SET

    def load_relations(self, user_store):
        if self.user is None and self.role is None:
            self._logger.warning("ACL is associated to an unknown object")
            self.default = "deny"
        elif self.default == "":
            if self.user is not None:
                self.default = "inherit"
            elif self.role is not None:
                self.default = "deny"

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

        default_str_low = self.default.lower()
        if default_str_low == "deny":
            self.user_set = EMPTY_USER_SET
        elif default_str_low == "allow":
            self.user_set = WHOLE_USER_SET
        elif default_str_low == "inherit":
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

    def allows_packet(self, pkt, src_user):
        if pkt is None:
            return ACLResult(src_user in self.user_set, PacketMatch())

        eth = pkt.get_protocol(ethernet.ethernet)
        return ACLResult(src_user in self.user_set,
                         PacketMatch(dl_dst=eth.dst))

    def __repr__(self):
        repr_family = ""
        if self.is_family:
            repr_family = " family"
        repr_public = ""
        if self.is_public:
            repr_public = " public"

        return "<UserACL{0}{1} allowed_users={2}>".format(
            repr_family, repr_public, self.allowed_user_names
        )

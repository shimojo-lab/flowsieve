from yamada.acl.base_set import BaseSet


class ServiceSet(BaseSet):
    """Represents a set of services"""
    def __init__(self, services=[], predicate=lambda s: False):
        assert isinstance(services, list) or isinstance(services, set)
        services = set(services)

        super(ServiceSet, self).__init__(
            lambda s: s in services or predicate(s)
        )

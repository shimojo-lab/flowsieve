class BaseSet(object):
    """Represents a set of items"""
    def __init__(self, predicate):
        super(BaseSet, self).__init__()
        self.predicate = predicate

    def __contains__(self, elem):
        """Check if element is contained in this set"""
        return self.predicate(elem)

    def __add__(self, other):
        """Compute union set"""
        assert isinstance(other, self.__class__)
        return self.__class__(predicate=lambda x: x in self or x in other)

    union = __add__

    def __sub__(self, other):
        """Compute difference set"""
        assert isinstance(other, self.__class__)
        return self.__class__(predicate=lambda x: x in self and x not in other)

    difference = __sub__

    def __and__(self, other):
        """Compute intersection set"""
        assert isinstance(other, self.__class__)
        return self.__class__(predicate=lambda x: x in self and x in other)

    intersection = __and__

    def __pos__(self):
        return self.__class__(predicate=lambda x: x in self)

    def __neg__(self):
        """Compute complementary set"""
        return self.__class__(predicate=lambda x: x not in self)

    @classmethod
    def whole(cls):
        return cls(predicate=lambda x: True)

    @classmethod
    def empty(cls):
        return cls(predicate=lambda x: False)

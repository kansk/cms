# Common definitions
# Simulated enumeration function


def enum(**named_values):
    return type('Enum', (), named_values)

# Get variable's name


def name(**variables):
    var_name = [x for x in variables]
    return var_name[0]

# Random string generator


def gen_random_str(str_len=6):
    import random
    import string
    return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.lowercase + string.digits) for _ in range(str_len))


# Enumerations

# Error codes
ERROR_CODE = {
    1000: 'No Error',
    1001: 'Invalid Client ID',
    1002: 'No Client ID: Client identifier is required',
    1003: 'Invalid GrantType',
    1004: 'Unsupported Grant Type',
    1005: 'Missing Required param : username',
    1006: 'Missing Required param : password',
    1007: 'Missing Required param : grant_type',
    1008: 'Invalid Refresh Token',
    1009: 'Refresh Token expired',
    1010: 'Invalid Scope',
    1011: 'Invalid Access Token',
    1012: 'Invalid Resource',
    1013: 'Access Token expired',
    1014: 'Endpoint Not found',
    2001: 'Invalid Response Received',
    2002: 'Invalid Input',
    10001: 'Unknown Error'
}

REQUEST_STATUS = enum(OK=True,
                      NOK=False)

# Common Utility classes and defitions
# Singleton Meta Class


class SingletonMetaClass(type):

    def __init__(cls, name, bases, dict):
        super(SingletonMetaClass, cls)\
            .__init__(name, bases, dict)
        original_new = cls.__new__

        def my_new(cls, *args, **kwds):
            if cls.instance == None:
                cls.instance = \
                    original_new(cls, *args, **kwds)
            return cls.instance
        cls.instance = None
        cls.__new__ = staticmethod(my_new)

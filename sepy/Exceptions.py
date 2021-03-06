#!/usr/bin/python3

class TokenExpiredException(Exception):
    pass

class RegistrationFailedException(Exception):
    pass

class TokenRequestFailedException(Exception):
    pass

class JSAPParsingException(Exception):
    pass

class YSAPParsingException(Exception):
    pass

class YSKParsingException(Exception):
    pass
    
class WrongFileException(Exception):
    pass

class ConfigurationParsingException(Exception):
    pass

class SubscriptionFailedException(Exception):
    pass
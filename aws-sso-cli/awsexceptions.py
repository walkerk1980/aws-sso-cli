class Error(Exception):
    """Base class for exceptions in this module."""
    pass

class AuthCodeError(Error):
    def __init__(self, message):
        self.message = message

class AccessTokenError(Error):
    def __init__(self, message):
        self.message = message

class SAMLAssertionError(Error):
    def __init__(self, message):
        self.message = message

class ApplicationInstancesError(Error):
    def __init__(self, message):
        self.message = message

class InputError(Error):
    """Exception raised for errors in the input.

    Attributes:
        expression -- input expression in which the error occurred
        message -- explanation of the error
    """

    def __init__(self, expression, message):
        self.expression = expression
        self.message = message

class TransitionError(Error):
    """Raised when an operation attempts a state transition that's not
    allowed.

    Attributes:
        previous -- state at beginning of transition
        next -- attempted new state
        message -- explanation of why the specific transition is not allowed
    """

    def __init__(self, previous, next, message):
        self.previous = previous
        self.next = next
        self.message = message

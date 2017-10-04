class BaseException(Exception):
    def __init__(self, message=None) -> None :
	    super().__init__()
	    self.message = message

class ResourceValidationError(BaseException):
	pass

class OpenStackDeploymentError(BaseException):
	pass
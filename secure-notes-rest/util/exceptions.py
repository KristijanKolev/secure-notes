from rest_framework.exceptions import APIException


class CustomStatusError(APIException):
    def __init__(self, status_code, detail=None, code=None):
        self.status_code = status_code
        super().__init__(detail, code)

from flask import request
from os import environ

class Parameters:

    def get(self, key, default=None, type=None, onlyEnv=True):
        '''
            Returns the value from the key.
            First check environment variables.
            Second check request headers if "onlyEnv=False".
        '''
        value = default

        if key in environ:
            value = environ.get(key)
        elif not onlyEnv:
            try:
                if key in request.headers:
                    value = request.headers.get(key)
            except RuntimeError:
                pass

        if (type is None) or (default is None):
            return value

        if type==bool:
            return value=="True"

        return type(value)
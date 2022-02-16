import json
from datetime import datetime, timezone
from aldap.http import HTTP
from aldap.parameters import Parameters


class Logs:

    def __init__(self, objectName:str, includeRequestIP:bool=True):
        self.param = Parameters()
        self.http = HTTP()

        self.objectName = objectName
        self.level = self.param.get('LOG_LEVEL', default='INFO')
        self.format = self.param.get('LOG_FORMAT', default='JSON')
        self.includeRequestIP = includeRequestIP

    def __print__(self, level:str, extraFields:dict):
        fields = {
            'date': datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            'level': level,
            'objectName': self.objectName,
            # 'base-url': self.http.getRequestBaseURL(),
            # 'referrer': self.http.getRequestReferrer()
        }

        # Include request IP
        if self.includeRequestIP:
            fields['ip'] = self.http.getRequestIP()

        # Include extra fields custom by the user
        if extraFields is not None:
            fields.update(extraFields)

        if self.format == 'JSON':
            print(json.dumps(fields))
        else:
            print(' - '.join(map(str, fields.values())))

    def error(self, extraFields:dict=None):
        if self.level in ['DEBUG', 'INFO', 'WARNING', 'ERROR']:
            self.__print__('ERROR', extraFields)

    def warning(self, extraFields:dict=None):
        if self.level in ['DEBUG', 'INFO', 'WARNING']:
            self.__print__('WARNING', extraFields)

    def info(self, extraFields:dict=None):
        if self.level in ['DEBUG', 'INFO']:
            self.__print__('INFO', extraFields)

    def debug(self, extraFields:dict=None):
        if self.level in ['DEBUG']:
            self.__print__('DEBUG', extraFields)

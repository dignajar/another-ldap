from flask import request

class HTTP:

    def getRequestIP(self):
        '''
            Returns the request IP
        '''
        if request.environ.get('HTTP_X_REAL_IP') is not None:
            return request.environ.get('HTTP_X_REAL_IP')
        elif request.environ.get('HTTP_X_FORWARDED_FOR') is not None:
            return request.environ.get('HTTP_X_FORWARDED_FOR')
        else:
            return request.remote_addr

    def getRequestReferrer(self):
        '''
            Returns the request referrer
        '''
        return request.referrer

    def getRequestBaseURL(self):
        '''
            Returns the request base URL
        '''
        return request.base_url
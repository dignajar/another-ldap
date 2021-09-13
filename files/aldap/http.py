from flask import request

class HTTP:

    def getRequestIP(self):
        '''
            Returns the request IP
        '''

        # Nginx Ingress Controller returns the X-Forwarded-For in X-Original-Forwarded-For
        # The last IP from the list is the client IP
        if request.environ.get('HTTP_X_ORIGINAL_FORWARDED_FOR') is not None:
            nginxControllerIP = request.environ.get('HTTP_X_ORIGINAL_FORWARDED_FOR')
            nginxControllerIP = [x.strip() for x in nginxControllerIP.split(',')]
            return nginxControllerIP[-1]

        if request.environ.get('HTTP_X_REAL_IP') is not None:
            return request.environ.get('HTTP_X_REAL_IP')

        if request.environ.get('HTTP_X_FORWARDED_FOR') is not None:
            return request.environ.get('HTTP_X_FORWARDED_FOR')

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
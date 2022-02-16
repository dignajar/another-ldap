import redis
from datetime import datetime
from aldap.parameters import Parameters
from aldap.logs import Logs


class Prometheus:

    def __init__(self):
        self.param = Parameters()
        self.logs = Logs(self.__class__.__name__, False)

        # Redis server
        self.enabled = self.param.get('PROMETHEUS', False, bool)
        self.redis_host = self.param.get('REDIS_HOST', 'localhost', str)
        self.redis_port = self.param.get('REDIS_PORT', 6379, int)
        self.redis_metric_expiration = self.param.get('REDIS_METRIC_EXPIRATION', 600, int)  # 600 seconds == 10 minutes

        if self.enabled:
            self.logs.debug({'message': 'Connecting to Redis.'})
            try:
                self.redis = redis.Redis(host=self.redis_host, port=self.redis_port, db=0, decode_responses=True)
                self.redis.ping()
                self.logs.debug({'message': 'Connected to Redis.'})
            except redis.exceptions.RedisError:
                self.enabled = False
                self.logs.error({'message': 'There was an error trying to connect to Redis.'})

    def addMetric(self, key, value):
        '''
        Add item to Redis, key => value
        '''
        if not self.enabled:
            return False
        value = 'aldap_'+value  # Add prefix "aldap_" to the metric
        self.redis.set(key, value)
        self.redis.expire(key, self.redis_metric_expiration)
        return True

    def addLastConnection(self, username:str):
        '''
        Add user last connection to Redis in Prometheus format
        '''
        if not self.enabled:
            return False
        self.addMetric('last_connection_'+username, 'last_connection{username="'+username+'", date="'+str(datetime.now())+'"} 1')
        return True

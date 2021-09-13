import ldap
import time
import re
from itertools import repeat
from aldap.logs import Logs
from aldap.parameters import Parameters

class Aldap:

    def __init__(self):
        self.param = Parameters()
        self.logs = Logs(self.__class__.__name__)

        self.ldapEndpoint = self.param.get('LDAP_ENDPOINT', default='')
        self.searchBase = self.param.get('LDAP_SEARCH_BASE')
        self.dnUsername = self.param.get('LDAP_MANAGER_DN_USERNAME')
        self.dnPassword = self.param.get('LDAP_MANAGER_PASSWORD')
        self.bindDN = self.param.get('LDAP_BIND_DN')
        self.searchFilter = self.param.get('LDAP_SEARCH_FILTER')
        self.allowedUsers = self.param.get('LDAP_ALLOWED_USERS', default=None, type=str, onlyEnv=False)
        self.allowedGroups = self.param.get('LDAP_ALLOWED_GROUPS', default=None, type=str, onlyEnv=False)
        self.condGroups = self.param.get('LDAP_CONDITIONAL_GROUPS', default='or', type=str, onlyEnv=False)
        self.condUsersGroups = self.param.get('LDAP_CONDITIONAL_USERS_GROUPS', default='or', type=str, onlyEnv=False)
        if self.allowedUsers is not None:
            self.allowedUsers = [x.strip() for x in self.allowedUsers.split(',')] # Convert string to list and trim each item
        if self.allowedGroups is not None:
            self.allowedGroups = [x.strip() for x in self.allowedGroups.split(',')] # Convert string to list and trim each item

    def connect(self):
        '''
            Returns LDAP object instance by opening LDAP connection to LDAP host
        '''
        self.logs.debug({'message':'Connecting to LDAP server.'})
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        connect = ldap.initialize(self.ldapEndpoint)
        connect.set_option(ldap.OPT_REFERRALS, 0)
        connect.set_option(ldap.OPT_DEBUG_LEVEL, 255)
        return connect

    def authentication(self, username:str, password:str) -> bool:
        '''
            Authenticate user by username and password
        '''
        connect = self.connect()

        finalUsername = username
        if self.bindDN:
            finalUsername = self.bindDN.replace("{username}", username)

        self.logs.debug({'message':'Authenticating user via LDAP.', 'username': username, 'finalUsername': finalUsername})

        start = time.time()
        try:
            connect.simple_bind_s(finalUsername, password)
            end = time.time()-start
            self.logs.info({'message':'Authentication successful via LDAP.', 'username': username, 'elapsedTime': str(end)})
            return True
        except ldap.INVALID_CREDENTIALS:
            self.logs.warning({'message':'Authentication failed via LDAP, invalid credentials.', 'username': username})
        except ldap.LDAPError as e:
            self.logs.error({'message':'There was an error trying to bind: %s' % e})

        return False

    def __getTree__(self, searchFilter:str) -> list:
        '''
            Returns the AD tree for the user, the user is search by the searchFilter
        '''
        connect = self.connect()
        result = []
        try:
            start = time.time()
            connect.simple_bind_s(self.dnUsername, self.dnPassword)
            result = connect.search_s(self.searchBase, ldap.SCOPE_SUBTREE, searchFilter)
            end = time.time()-start
            self.logs.debug({'message':'Searched by filter.', 'filter': searchFilter, 'elapsedTime': str(end)})
        except ldap.LDAPError as e:
            self.logs.error({'message':'There was an error trying to bind: %s' % e})

        return result

    def __decode__(self, word:bytes) -> str:
        '''
            Convert binary to string. b'test' => 'test'
        '''
        return word.decode("utf-8")

    def __findMatch__(self, group:str, adGroup:str):
        try:
            # Extract the Common Name from the string (letters, spaces, underscores and hyphens)
            adGroup = re.search(r'(?i)CN=((\w*\s?_?-?)*)', adGroup).group(1)
        except Exception as e:
            self.logs.warning({'message':'There was an error trying to search CN: %s' % e})
            return None

        adGroup = adGroup.lower()
        group = group.lower()

        # Return match against supplied group/pattern (None if there is no match)
        try:
            return re.fullmatch(f'{group}.*', adGroup).group(0)
        except:
            return None

    def getUserGroups(self, username:str):
        '''
            Returns user's groups
        '''
        self.logs.debug({'message':'Getting user\'s groups.'})
        searchFilter = self.searchFilter.replace("{username}", username)
        tree = self.__getTree__(searchFilter)

        # Crawl tree and extract the groups of the user
        adGroups = []
        for zone in tree:
            for element in zone:
                try:
                    adGroups.extend(element['memberOf'])
                except:
                    pass
        # Create a list from the elements and convert binary to str the items
        adGroups = list(map(self.__decode__,adGroups))
        return adGroups

    def validateAllowedGroups(self, username:str, groups:list, allowedGroups:list, condGroups:str='or'):
        '''
            Validate user's groups.
            Returns True and matched groups if the groups are valid for the user, False otherwise.
        '''
        # Get the groups from the AD if they are not send via parameters
        adGroups = groups
        if groups is None:
            adGroups = self.getUserGroups(username)

        self.logs.debug({'message':'Validating AD groups.', 'username': username, 'allowedGroups': ','.join(allowedGroups), 'conditional': condGroups})
        matchedGroups = []
        matchesByGroup = []
        for group in allowedGroups:
            matches = list(filter(None,list(map(self.__findMatch__, repeat(group), adGroups))))
            if matches:
                matchesByGroup.append((group,matches))
                matchedGroups.extend(matches)

        # Conditiona OR, true if just 1 group match
        if condGroups == 'or':
            if len(matchedGroups) > 0:
                self.logs.info({'message':'At least one group is valid for the user.', 'username': username, 'matchedGroups': ','.join(matchedGroups), 'allowedGroups': ','.join(allowedGroups), 'conditional': condGroups})
                return True, matchedGroups
        # Conditiona AND, true if all the groups match
        elif condGroups == 'and':
            if len(allowedGroups) == len(matchesByGroup):
                self.logs.info({'message':'All groups are valid for the user.', 'username': username, 'matchedGroups': ','.join(matchedGroups), 'allowedGroups': ','.join(allowedGroups), 'conditional': condGroups})
                return True, matchedGroups
        else:
            self.logs.warning({'message':'Invalid conditional group.', 'username': username, 'conditional': condGroups})
            return False, []

        self.logs.warning({'message':'Invalid groups for the user.', 'username': username, 'matchedGroups': ','.join(matchedGroups), 'allowedGroups': ','.join(allowedGroups), 'conditional': condGroups})
        return False, []

    def validateAllowedUsers(self, username:str, allowedUsers:list):
        '''
            Validate if the user is inside the allowed-user list.
            Returns True if the user is inside the list, False otherwise.
        '''
        self.logs.debug({'message':'Validating allowed-users list.', 'username': username, 'allowedUsers': ','.join(allowedUsers)})
        for user in allowedUsers:
            if username.lower() == user.strip().lower():
                self.logs.info({'message':'User inside the allowed-user list.', 'username': username, 'allowedUsers': ','.join(allowedUsers)})
                return True
        self.logs.info({'message':'User not found inside the allowed-user list.', 'username': username, 'allowedUsers': ','.join(allowedUsers)})
        return False

    def authorization(self, username:str, groups:list):
        # Check allowed users
        if self.allowedUsers is not None:
            validAllowedUsers = self.validateAllowedUsers(username, self.allowedUsers)
            if validAllowedUsers:
                if self.condUsersGroups=='or':
                    return True, []
            else:
                if self.condUsersGroups=='and':
                    return False, []

        # Check allowed groups
        if self.allowedGroups is not None:
            validAllowedGroups, matchedGroups = self.validateAllowedGroups(username, groups, self.allowedGroups, self.condGroups)
            if validAllowedGroups:
                return True, matchedGroups
            return False, []

        return True, []
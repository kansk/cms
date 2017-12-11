import requests
import json
import httplib

from logger import LOG_INFO, LOG_WARN, LOG_CRIT, LOG_DEBUG, LOG_ERR
from iam_proxy_common import SingletonMetaClass, ERROR_CODE, REQUEST_STATUS
import global_config

# from iam_proxy_common import SingletonMetaClass, ERROR_CODE, REQUEST_STATUS
# import global_config


class OAuthToken:

    def __init__(self, token, refresh_token, expiry, scope, status, error_code=None, error_message=None):
        self._token = token
        self._refresh_token = refresh_token
        self._expiry = expiry
        self._scope = scope
        self._status = status
#         self._status = True
        if(not error_code):
            self._error_code = 1000
        else:
            self._error_code = error_code
        if(not error_message):
            self._error_message = ERROR_CODE[1000]
        else:
            self._error_message = error_message

        LOG_DEBUG('OAuth Token created with token:{}, refresh token:{}, expiry:{}, status:{}, error code:{}, error message:{}'
                  .format(self._token, self._refresh_token, self._expiry,
                          self._status, self._error_code, self._error_message))

    def get_status(self):
        return self._status

    def get_access_token(self):
        return self._token

    def get_scope(self):
        return self._scope

    def get_refresh_token(self):
        return self._refresh_token

    def get_expiry(self):
        return self._expiry

    def get_errorcode(self):
        return self._error_code

    def get_errorjson(self):
        return {'error_code': self._error_code, 'error_message': self._error_message}


class IAMProxy:
    __metaclass__ = SingletonMetaClass

    def __init__(self, iam_endpoint):
        from urlparse import urlparse
        try:
            parsed_url = urlparse(iam_endpoint)
        except Exception as parse_exception:
            raise Exception(parse_exception)

        self.iam_endpoint = iam_endpoint

    def register_module(self, module_name, module_endpoint, target_apis, username, password):
        LOG_INFO('Registering {} reachable at {}'.format(
            module_name, module_endpoint))
#         login_response = requests.post(login_url, json=login_input)
        # Login before registration
        oauth_token = self.login(username, password)
        if(oauth_token and oauth_token.get_status() == REQUEST_STATUS.OK):
            register_input = {}
            register_input['target_apis'] = target_apis
            register_input['module_name'] = module_name
            register_input['module_end_point'] = module_endpoint

            register_url = self.iam_endpoint + \
                global_config.IAM_MOD_REGISTER_URI

            try:
                register_response = requests.post(
                    register_url, data=json.dumps(register_input))
                # If Registration is successful, nothing to do, just
                # return the the token object from login, else create
                # a new token object with registration error
                if register_response.status_code != httplib.OK:
                    LOG_ERR('Registration Failed with error: {}'.format(
                        register_response.status_code))
                    json_response = register_response.json()
                    # Check that at least error code is present in response
                    if('error_code' in json_response and
                            'error_message' in json_response):
                        LOG_ERR('Registration failed with error: {}'.format(
                            json_response['error_message']))
                        oauth_token = OAuthToken(None,
                                                 None,
                                                 None,
                                                 None,
                                                 REQUEST_STATUS.NOK,
                                                 json_response['error_code'],
                                                 json_response['error_message'])
                    else:
                        LOG_ERR(
                            'Invalid response received during registration')
                        oauth_token = OAuthToken(None,
                                                 None,
                                                 None,
                                                 None,
                                                 REQUEST_STATUS.NOK,
                                                 2001,
                                                 ERROR_CODE[2001])

#                     login_response.raise_for_status()

                else:
                    LOG_INFO('Registration Successful')

            except ValueError as ve:
                LOG_ERR(
                    'Invalid response received for registration request:{}'.format(ve))
            except requests.exceptions.HTTPError as he:
                LOG_ERR(
                    'Registration request failed. Error from server:{}'.format(he))
            except requests.exceptions.ConnectionError as ce:
                LOG_ERR(
                    'Registration request failed due to connection error: {}.'.format(ce))
            except requests.exceptions.Timeout as to:
                LOG_ERR('Registration request timed-out.')
            except Exception as ex:
                LOG_ERR('Unknown exception during Registration:{}.'.format(ex))

        else:
            LOG_ERR('Registration Failed to login failure')

        return oauth_token

    def is_token_valid(self, bearer_token):
        if(not bearer_token):
            LOG_ERR('Token Validation request missing token')
            return OAuthToken(None, None, None, None,
                              REQUEST_STATUS.NOK,
                              2002,
                              ERROR_CODE[2002])

        LOG_DEBUG('Validating bearer token:{}'.format(bearer_token))
        token_validate_url = self.iam_endpoint + \
            global_config.IAM_TOKEN_VALIDATE_URI + bearer_token

        try:
            token_validate_response = requests.get(token_validate_url,
                                                   auth=(global_config.PROXY_CLIENT_ID,
                                                         global_config.PROXY_CLIENT_KEY))
            token_validate_json = token_validate_response.json()
            if token_validate_response.status_code != httplib.OK:
                # Check that at least error code is present in response
                if('error_code' in token_validate_json and
                        'error_message' in token_validate_json):
                    LOG_ERR('Request for validating token failed with error: {}'
                            .format(token_validate_json['error_message']))
                    # Create dummy token object
                    return OAuthToken(None,
                                      None,
                                      None,
                                      None,
                                      REQUEST_STATUS.NOK,
                                      token_validate_json['error_code'],
                                      token_validate_json['error_message'])
                else:
                    LOG_ERR(
                        'Unexpected JSON response "{}" received'.format(token_validate_json))
                    # Create dummy token object
                    return OAuthToken(None,
                                      None,
                                      None,
                                      None,
                                      REQUEST_STATUS.NOK,
                                      2001,
                                      ERROR_CODE[2001])
            else:
                LOG_INFO('Token Validated')
                # Response includes too many details,
                # no one interested now, so don't report :(
                LOG_DEBUG('Validated response:{}'.format(token_validate_json))
                # Create dummy token object
                return OAuthToken(None,
                                  None,
                                  None,
                                  None,
                                  REQUEST_STATUS.OK,
                                  None,
                                  None)

        except ValueError as ve:
            LOG_ERR(
                'Invalid response received while validating token:{}'.format(ve))
        except requests.exceptions.HTTPError as he:
            LOG_ERR(
                'Request for validating token failed. Error from server:{}'.format(he))
        except requests.exceptions.ConnectionError as ce:
            LOG_ERR(
                'Request for validating token failed due to connection error: {}.'.format(ce))
        except requests.exceptions.Timeout as to:
            LOG_ERR('Request for validating token timed-out.')
        except Exception as ex:
            LOG_ERR('Unknown exception while validating token:{}.'.format(ex))

        # Flow should never reach here
        return OAuthToken(None, None, None, None, REQUEST_STATUS.NOK,
                          10001, ERROR_CODE[10001])

    def refresh_token(self, refresh_token):
        oauth_token = None
        LOG_INFO('Refreshing token')
        LOG_DEBUG('Attempting token refresh with {}'.format(refresh_token))
#         login_response = requests.post(login_url, json=login_input)

        refresh_token_input = {}
        refresh_token_input['grant_type'] = global_config.OAUTH_REFRESH_GRANT
        refresh_token_input['refresh_token'] = refresh_token
        refresh_token_input['client_id'] = global_config.PROXY_CLIENT_ID
        refresh_token_input['client_pw'] = global_config.PROXY_CLIENT_KEY

        refresh_token_url = self.iam_endpoint + \
            global_config.IAM_REFRESH_TOKEN_URI

        try:
            refresh_token_response = requests.post(
                refresh_token_url, data=json.dumps(refresh_token_input))
            if refresh_token_response.status_code == httplib.OK:
                LOG_INFO('Token Refresh Successful')
                token_response = refresh_token_response.json()
                # Check that mandatory parameters are present in response
                if('access_token' in token_response and
                        'refresh_token' in token_response and
                        'scope' in token_response and
                        'token_type' in token_response and
                        'expires_in' in token_response):
                    # Create a token object from the response
                    oauth_token = OAuthToken(token_response['access_token'],
                                             token_response['refresh_token'],
                                             token_response['expires_in'],
                                             token_response['scope'],
                                             REQUEST_STATUS.OK)
                else:
                    LOG_INFO('No token received after token refresh')
                    # Check that at least error code is present in response
                    if('error_code' in token_response and
                            'error_message' in token_response):
                        # Create incomplete object
                        LOG_ERR('Token Refresh failed with error: {}'.format(
                            token_response['error_message']))
                        oauth_token = OAuthToken(None,
                                                 None,
                                                 None,
                                                 None,
                                                 REQUEST_STATUS.NOK,
                                                 token_response['error_code'],
                                                 token_response['error_message'])
                    else:
                        LOG_ERR(
                            'Invalid Token response received during refresh')
                        # Create incomplete object
                        oauth_token = OAuthToken(None,
                                                 None,
                                                 None,
                                                 None,
                                                 REQUEST_STATUS.NOK,
                                                 2001,
                                                 ERROR_CODE[2001])
            else:
                LOG_ERR('Token Refresh failed with unhandled error')
#                 login_response.raise_for_status()

        except ValueError as ve:
            LOG_ERR(
                'Invalid response received for token refresh request:{}'.format(ve))
        except requests.exceptions.HTTPError as he:
            LOG_ERR(
                'Token Refresh request failed. Error from server:{}'.format(he))
        except requests.exceptions.ConnectionError as ce:
            LOG_ERR(
                'Token Refresh request failed due to connection error: {}.'.format(ce))
        except requests.exceptions.Timeout as to:
            LOG_ERR('Token Refresh request timed-out.')
        except Exception as ex:
            LOG_ERR('Unknown exception during Token Refresh:{}.'.format(ex))

        return oauth_token

    def get_endpoints(self, bearer_token, module_name=None):
        LOG_DEBUG('Getting endpoints with bearer :{}'.format(bearer_token))

        if(module_name):
            endpoints_url = self.iam_endpoint + \
                global_config.IAM_GET_EP_URI + '/' + module_name.encode('utf8')
        else:
            endpoints_url = self.iam_endpoint + global_config.IAM_GET_EP_URI

        auth_header = {'Content-Type': 'application/x-www-form-urlencoded',
                       'Authorization': str('Bearer ' + bearer_token)}

        try:
            endpoints_response = requests.get(
                endpoints_url, headers=auth_header)
            endpoints_json = endpoints_response.json()
            if endpoints_response.status_code != httplib.OK:
                # Check that at least error code is present in response
                if('error_code' in endpoints_json and
                        'error_message' in endpoints_json):
                    LOG_ERR('Request for Endpoints failed with error: {}'
                            .format(endpoints_json['error_message']))
                else:
                    LOG_ERR(
                        'Unexpected JSON response "{}" received'.format(endpoints_json))
                    endpoints_json = {
                        'error_code': 2001, 'error_message': ERROR_CODE[2001]}
            else:
                LOG_INFO('Endpoints received')

            return endpoints_json

        except ValueError as ve:
            LOG_ERR(
                'Invalid response received while getting endpoints:{}'.format(ve))
        except requests.exceptions.HTTPError as he:
            LOG_ERR(
                'Request for getting endpoints failed. Error from server:{}'.format(he))
        except requests.exceptions.ConnectionError as ce:
            LOG_ERR(
                'Request for getting endpoints failed due to connection error: {}.'.format(ce))
        except requests.exceptions.Timeout as to:
            LOG_ERR('Request for getting endpoints timed-out.')
        except Exception as ex:
            LOG_ERR('Unknown exception while getting endpoints:{}.'.format(ex))

        # Flow should never reach here
        return {'error_code': 10001, 'error_message': ERROR_CODE[10001]}

    def login(self, username, password):
        oauth_token = None
        LOG_INFO('Logging in')
        LOG_DEBUG('{} logging in'.format(username))

        login_input = {}
        login_input['username'] = username
        login_input['password'] = password
        login_input['grantType'] = global_config.OAUTH_GRANT_TYPE
        login_input['clientId'] = global_config.PROXY_CLIENT_ID
        login_input['clientPassword'] = global_config.PROXY_CLIENT_KEY

        login_url = self.iam_endpoint + global_config.IAM_USER_LOGIN_URI

        try:
            login_response = requests.post(login_url, data=json.dumps(login_input))
            if login_response.status_code == httplib.OK:
                LOG_INFO('Login Successful')
                token_response = login_response.json()
                # Check that mandatory parameters are present in response
                if('access_token' in token_response and
                        'refresh_token' in token_response and
                        'scope' in token_response and
                        'token_type' in token_response and
                        'expires_in' in token_response):
                    # Create a token object from the response
                    oauth_token = OAuthToken(token_response['access_token'],
                                             token_response['refresh_token'],
                                             token_response['expires_in'],
                                             token_response['scope'],
                                             REQUEST_STATUS.OK)
                else:
                    LOG_INFO('No token received after login')
                    # Check that at least error code is present in response
                    if('error_code' in token_response and
                            'error_message' in token_response):
                        # Create incomplete object
                        LOG_ERR(
                            'Login failed with error: {}'.format(token_response['error_message']))
                        oauth_token = OAuthToken(None,
                                                 None,
                                                 None,
                                                 None,
                                                 REQUEST_STATUS.NOK,
                                                 token_response['error_code'],
                                                 token_response['error_message'])
                    else:
                        LOG_ERR('Invalid Token response received during login')
                        # Create incomplete object
                        oauth_token = OAuthToken(None,
                                                 None,
                                                 None,
                                                 None,
                                                 REQUEST_STATUS.NOK,
                                                 2001,
                                                 ERROR_CODE[2001])

            else:
                LOG_ERR('Login Failed with unhandled error')
                login_response.raise_for_status()

        except ValueError as ve:
            LOG_ERR(
                'Invalid response received for login request:{}'.format(ve))
        except requests.exceptions.HTTPError as he:
            LOG_ERR('Login request failed. Error from server:{}'.format(he))
        except requests.exceptions.ConnectionError as ce:
            LOG_ERR(
                'Login request failed due to connection error: {}.'.format(ce))
        except requests.exceptions.Timeout as to:
            LOG_ERR('Login request timed-out.')
        except Exception as ex:
            LOG_ERR('Unknown exception during login:{}.'.format(ex))

        return oauth_token

    def logoff(self, bearer_token):
        LOG_DEBUG('Logging off user with bearer :{}'.format(bearer_token))

        token_revoke_url = self.iam_endpoint + \
            global_config.IAM_TOKEN_REVOKE_URI

        auth_header = {'Authorization': str('Bearer ' + bearer_token)}

        try:
            token_revoke_response = requests.get(
                token_revoke_url, headers=auth_header)
            if token_revoke_response.status_code != httplib.OK:
                # I am only interested in response JSON if request failed
                token_revoke_json = token_revoke_response.json()
                # Check that at least error code is present in response
                if('error_code' in token_revoke_json and
                        'error_message' in token_revoke_json):
                    LOG_ERR('Request for logoff failed with error: {}'
                            .format(token_revoke_json['error_message']))
                    # Create incomplete object
                    oauth_token = OAuthToken(None,
                                             None,
                                             None,
                                             None,
                                             REQUEST_STATUS.NOK,
                                             token_revoke_json['error_code'],
                                             token_revoke_json['error_message'])
                else:
                    LOG_ERR(
                        'Unexpected JSON response "{}" received'.format(token_revoke_json))
                    # Create incomplete object
                    oauth_token = OAuthToken(None,
                                             None,
                                             None,
                                             None,
                                             REQUEST_STATUS.NOK,
                                             2001,
                                             ERROR_CODE[2001])
            else:
                LOG_INFO('User logged off')
                # Create incomplete object
                oauth_token = OAuthToken(None,
                                         None,
                                         None,
                                         None,
                                         REQUEST_STATUS.OK,
                                         None,
                                         None)

            return oauth_token

        except ValueError as ve:
            LOG_ERR(
                'Invalid response received while logging off:{}'.format(ve))
        except requests.exceptions.HTTPError as he:
            LOG_ERR(
                'Request for logging off failed. Error from server:{}'.format(he))
        except requests.exceptions.ConnectionError as ce:
            LOG_ERR(
                'Request for logging off failed due to connection error: {}.'.format(ce))
        except requests.exceptions.Timeout as to:
            LOG_ERR('Request for logging off timed-out.')
        except Exception as ex:
            LOG_ERR('Unknown exception while logging off:{}.'.format(ex))

        # Flow should never reach here
        return OAuthToken(None, None, None, None, REQUEST_STATUS.NOK,
                          10001, ERROR_CODE[10001])


# Perpetual Timer Class
from threading import Timer, Lock
import time


class PerpetualTimer:

    def __init__(self, period, worker, **worker_kwargs):
        self.period = period
        self.worker = worker
        self.worker_kwargs = worker_kwargs
        self.is_stopped = False
        self.timer = Timer(self.period, self.handle_function)

    def handle_function(self):
        if(len(self.worker_kwargs)):
            self.worker(**self.worker_kwargs)
        else:
            self.worker()
        if(self.is_stopped == False):
            self.timer = Timer(self.period, self.handle_function)
            self.timer.start()

    def start(self):
        if(self.is_stopped == True):
            self.timer = Timer(self.period, self.handle_function)
            self.is_stopped = False

        self.timer.start()

    def stop(self):
        self.is_stopped = True
        self.timer.cancel()


class TokenManager:

    def __init__(self, access_token, refresh_token, expiry, iam_proxy_instance):
        self._access_token = access_token
        self._refresh_token = refresh_token
        self._expiry = int(expiry)
        self._iam_proxy_instance = iam_proxy_instance
        self._token_access_lock = Lock()

    def get_token(self):
        return self._access_token

    def start(self):
        # Refresh token every expiry - TOKEN_REFRESH_PREFETCH seconds period
        refresh_period = self._expiry - \
            int(global_config.TOKEN_REFRESH_PREFETCH)
        self.refresh_token_timer = PerpetualTimer(
            refresh_period, self.refresh_token)
        self.refresh_token_timer.start()
        LOG_INFO('Token refresh timer started. Refresh will be attempted every {} sec.'.format(
            refresh_period))

    def refresh_token(self):
        LOG_INFO('Attempting Token Refreshing')
        token = self._iam_proxy_instance.refresh_token(self._refresh_token)
        if(token):
            if(token.get_status() == True):
                self._token_access_lock.acquire()
                self._access_token = token.get_access_token()
                self._refresh_token = token.get_refresh_token()
                self._expiry = int(token.get_expiry())
                self._token_access_lock.release()
                self.restart_timer()
                LOG_INFO('Token Refresh Completed')
            else:
                LOG_ERR(
                    'Token Refresh attempt failed:{}'.format(token.get_errorjson()))
        else:
            LOG_ERR('Token Refresh attempt failed')

    def restart_timer(self):
        refresh_period = self._expiry - \
            int(global_config.TOKEN_REFRESH_PREFETCH)
        self.refresh_token_timer.stop()

        self.refresh_token_timer = PerpetualTimer(
            refresh_period, self.refresh_token)
        self.refresh_token_timer.start()
        LOG_INFO('Token refresh timer started. Refresh will be attempted every {} sec.'.format(
            refresh_period))

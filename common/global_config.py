import logging

LOGGER_NAME = 'IAMProxy'
LOG_REL_PATH = '.'
LOG_NAME = 'IAMProxy.log'
LOG_FORMAT = '[%(asctime)s] %(levelname)s [%(filename)s:%(lineno)d] - %(message)s'
LOG_LEVEL = logging.DEBUG


IAM_MOD_REGISTER_URI = '/auth/v1.5/target'
IAM_REFRESH_TOKEN_URI = '/auth/v1.5/oauth/token'
IAM_TOKEN_VALIDATE_URI = IAM_REFRESH_TOKEN_URI + '/'
IAM_USER_LOGIN_URI = '/auth/v1.5/oauth/login'
IAM_GET_EP_URI = '/auth/v1.5/endpoints'
IAM_TOKEN_REVOKE_URI = '/auth/v1.5/oauth/revoke-token'


OAUTH_GRANT_TYPE = 'password'
OAUTH_REFRESH_GRANT = 'refresh_token'
PROXY_CLIENT_ID = 'clientapp'
PROXY_CLIENT_KEY = '123456'

TOKEN_REFRESH_PREFETCH = 5

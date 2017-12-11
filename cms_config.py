MEC_APP_CATALOG_IP = "localhost"
MEC_APP_CATALOG_PORT = 60601 

MEC_CLOUDLET_CATALOG_IP = "localhost"
MEC_CLOUDLET_CATALOG_PORT = 60602

MEC_MICROSERVICE_CATALOG_IP = "localhost"
MEC_MICROSERVICE_CATALOG_PORT = 60617

MEC_IAM_PORT = 20010 
MEC_IAM_IP = "localhost"
#MEC_CMS_PORT = 0xed02
MEC_CMS_PORT = 0x17d2

MODULE_NAME = 'CMS'
CLOUDLET_CATALOG_URI = '/cloudletcatalog/'
APP_CATALOG_URI = '/applicationcatalog/'
MICRO_SVC_CATALOG_URI = '/microservicecatalog/'
CLC_SERVER_URI = '/api/v1.0/clc/'
IAM_URL_PATTERN = "http://%s:%d" % (MEC_IAM_IP, MEC_IAM_PORT)
SELF_HOSTED_AT = '/api/v1.0/llo/cms'
SELF_USER = 'cloud_api_admin'
SELF_PASSWORD = 'Admin@1234'
# Initialize connections with IAM
iam_proxy = None
token_manager = None
IAM_PLUGGED_IN = False

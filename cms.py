import json
import sys
import threading
import logging
import httplib
import requests
import collections
from functools import wraps
from flask import Flask, request, Response, abort
from cms_config import *
from common.iam_proxy import OAuthToken, IAMProxy, TokenManager

CMS = Flask(__name__)

def init_IAM_connections():
    # Return immediately if IAM proxy is not plugged in
    if not IAM_PLUGGED_IN:
        return

    global iam_proxy, token_manager
    iam_proxy = IAMProxy(IAM_URL_PATTERN)

    # Register Self with IAM
    self_hosted_endpoint = SELF_HOSTED_URL_PATTERN
    target_apis = [
        CLOUDLET_CATALOG_URI, APP_CATALOG_URI, MICRO_SVC_CATALOG_URI, CLC_SERVER_URI]
    token = iam_proxy.register_module(MODULE_NAME,
                                      self_hosted_endpoint, target_apis, SELF_USER, SELF_PASSWORD)

    if token.get_status() == True:
        logging.info('%s registered successfully with IAM'
                     % (MODULE_NAME))
        logging.debug('Access token received: {}'
                      .format(token.get_access_token()))
    else:
        logging.error('%s failed to register with IAM'
                      % (MODULE_NAME))
        logging.error('error: {}'
                      .format(token.get_errorjson()))

    # Start Token Management

    token_manager = TokenManager(token.get_access_token(),
                                 token.get_refresh_token(), token.get_expiry(), iam_proxy)

    token_manager.start()


# IAM Token Validation decorator
# TODO - To be replaced with a parameterized decorator
def iam_token_validate(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not IAM_PLUGGED_IN:
            return f(*args, **kwargs)
        global iam_proxy
        if not 'Authorization' in request.headers:
            # Abort
            auth_failure_response = {"error_code": "401",
                                     "error_message": "Authorization Required"}
            return Response(json.dumps(auth_failure_response),
                            mimetype='application/json',
                            status=httplib.UNAUTHORIZED)

        bearer_data = request.headers['Authorization']\
            .encode('ascii', 'ignore')
        bearer_token = str.replace(str(bearer_data), 'Bearer ', '')

        # Get IAM module to validate the token
        token = iam_proxy.is_token_valid(bearer_token)
        if token.get_status() == True:
            return f(*args, **kwargs)
        else:
            # Abort
            return Response(json.dumps(token.get_errorjson()),
                            mimetype='application/json',
                            status=httplib.UNAUTHORIZED)
    return decorated_function

def update_header(header):
    if IAM_PLUGGED_IN:
        auth_header = {'Authorization': str('Bearer ' + token_manager.get_token())}
        header.update(auth_header)
    return header

class CentralRepoHelper():

    def __init__(self):
        self.lock = threading.Lock()

    def load_db(self):
        self.db = None
        try:
            url = "http://%s:%d/cloudletcatalog/cloudlets" % (
                MEC_CLOUDLET_CATALOG_IP, MEC_CLOUDLET_CATALOG_PORT)
            headers = {}
            update_header(headers)
            db_data = requests.get(url, headers=headers)
            logging.info("Loading cloudlets database")
            self.db = json.loads(db_data.content)
        except:
            return Response(response="CLOUDLET-DISCOVERY INTERNAL_SERVER_ERROR",
                            status=httplib.INTERNAL_SERVER_ERROR)

    def find_cloudlets_with_env(self, environment):
        cloudlets_with_env = {}
        cloudlets_with_env['cloudlets'] = []
        self.load_db()
        cloudlets = self.db
        for cloudlet in cloudlets:
            if cloudlet['environment'] and cloudlet['environment'] == environment and (cloudlet['onBoardStatus']).lower() == "registered":
                return {cloudlet['cloudletName']: cloudlet}


def verify_and_update_microservice_metadata(metadata):
    for microservice in metadata['appMetadata']['microservices']:
        if microservice["subscribed"] == "Y":
            microservice_name = microservice["microServiceName"]
            url = "http://%s:%d/microservicecatalog/microservice/%s" % (
                MEC_MICROSERVICE_CATALOG_IP, MEC_MICROSERVICE_CATALOG_PORT, microservice_name)
            headers = {}
            update_header(headers)
            response = requests.get(url, headers=headers)
            microservice_metadata = json.loads(response.text)
            metadata["microserviceMetadata"].append(microservice_metadata)
    return metadata

@CMS.route('/api/v1.0/llo/cms/<developer_id>/<app_id>/<cloudlet_id>', methods=['POST'])
#@iam_token_validate
def provision_application(developer_id, app_id, cloudlet_id):
    logging.info("Recieved provision application with developer_id:%s, app_id:%s and cloudlet_id:%s" %(developer_id, app_id, cloudlet_id))
    client_id = ""
    extension = ""
    data = request.get_json()
    if data:
        client_id = data.get('clientId')
        extension = data.get('extensions')
        microservice = data.get('microservice')

    if not client_id:
        client_id = ""

    if microservice and microservice.lower() == "yes":
        # Get microservice metadata
        url = "http://%s:%d/microservicecatalog/microservice/%s" % (
            MEC_MICROSERVICE_CATALOG_IP, MEC_MICROSERVICE_CATALOG_PORT, app_id)
        logging.debug("Getting microservice metadata from url:%s" %(url))
        headers = {}
        update_header(headers)
        response = requests.get(url, headers=headers)
        data = json.loads(response.text)
        data = convert(data)
        microservice_metadata = data['metadata']

        logging.debug("Populating application metadata from microservice metadata")
        metadata = {}
        metadata["microserviceMetadata"] = []
        ms_metadata = {"microServiceName":data["microServiceName"], "tenancy":data["tenancy"], "metadata":data["metadata"]}
        if "deliveryMethod" in data:
            ms_metadata["deliveryMethod"] = data["deliveryMethod"]
        metadata["microserviceMetadata"].append(ms_metadata)
        metadata["appMetadata"] = {"microservices":[], "applicationType": data["microServiceType"].lower()}
        appmetadata_microservice = {}
        appmetadata_microservice["microServiceName"] = data["microServiceName"]
        appmetadata_microservice["exposed"] = {"networks":[], "events":[], "httpApis":[]}
        appmetadata_microservice["useAsLib"] = "N"
        appmetadata_microservice["resources"] = []
        appmetadata_microservice["subscribed"] = "N"
        if "deliveryMethod" in data:
            metadata["appMetadata"]["deliveryMethod"] = data["deliveryMethod"]

        # Get workload's list
        for workload in microservice_metadata["workloads"]:
            appmetadata_microservice_resource = {}
            appmetadata_microservice_resource["name"] = "default"
            appmetadata_microservice_resource["workloadName"] = workload["workloadName"]
            appmetadata_microservice["resources"].append(appmetadata_microservice_resource)

        # Get event's list
        for event in microservice_metadata["external"]["events"]:
            appmetadata_microservice_exposed_event = {}
            appmetadata_microservice_exposed_event["name"] = event
            appmetadata_microservice_exposed_event["exposedTo"] = ["app@client"]
            appmetadata_microservice["exposed"]["events"].append(appmetadata_microservice_exposed_event)

        # Get network's list
        for network in microservice_metadata["external"]["networks"]:
            appmetadata_microservice_exposed_network = {}
            appmetadata_microservice_exposed_network["name"] = network
            appmetadata_microservice_exposed_network["exposedTo"] = ["app@client"]
            appmetadata_microservice["exposed"]["networks"].append(appmetadata_microservice_exposed_network)

        # Get httpApi's list
        for httpApi in microservice_metadata["external"]["httpApis"]:
            appmetadata_microservice_exposed_httpApi = {}
            appmetadata_microservice_exposed_httpApi["name"] = httpApi
            appmetadata_microservice_exposed_httpApi["exposedTo"] = ["app@client"]
            appmetadata_microservice["exposed"]["httpApis"].append(appmetadata_microservice_exposed_httpApi)

        metadata["appMetadata"]["microservices"].append(appmetadata_microservice)
        logging.debug("Application metadata populated from microservice metadata")
    else:
        # Get application metadata
        url = "http://%s:%d/applicationcatalog/application/%s" % (
            MEC_APP_CATALOG_IP, MEC_APP_CATALOG_PORT, app_id)
        logging.debug("Getting application metadata from url:%s" %(url))
        headers = {}
        update_header(headers)
        response = requests.get(url, headers=headers)
        data = json.loads(response.text)
        metadata = verify_and_update_microservice_metadata(data['metadata'])

    # Get cloudlet details from central repository based on cloudlet_id
    url = "http://%s:%d/cloudletcatalog/cloudlet/%s" % (
        MEC_CLOUDLET_CATALOG_IP, MEC_CLOUDLET_CATALOG_PORT, cloudlet_id)
    logging.debug("Getting cloudlet details from central repository based on cloudlet_id from url:%s" %(url))
    resp = requests.get(url, headers=headers)
    data = json.loads(resp.text)
    ip = None
    port = None
    for endpoint in data['endpoints']:
        if endpoint['name'] == 'clc':
            ip = endpoint['ip']
            port = endpoint['port']

    # Call provision api of cloudlet controller with payload as metadata and client-id
    payload = {app_id: metadata, "clientId": client_id}
    if extension:
        payload['extensions'] = extension

    headers = {'content-type': 'application/json'}
    url = "http://%s:%s/api/v1.0/clc/%s/%s" % (
        str(ip), str(port), developer_id, app_id)
    logging.debug("Calling provision api of cloudlet controller with url:%s" %(url))
    response = requests.post(url, data=json.dumps(payload), headers=headers)
    logging.debug("Response from cloudlet controller %s" %(str(response.status_code)))
    if response.status_code == 200:
        return response.text
    else:
        return Response(response=response.reason, status=response.status_code)

#@CMS.route('/api/v1.0/llo/cms/<developer_id>/<app_id>/<cloudlet_id>', methods=['POST'])
##@iam_token_validate
#def provision_application(developer_id, app_id, cloudlet_id):
#    logging.info("Recieved provision application with developer_id:%s, app_id:%s and cloudlet_id:%s" %(developer_id, app_id, cloudlet_id))
#    client_id = ""
#    extension = ""
#    data = request.get_json()
#    if data:
#        client_id = data.get('clientId')
#        extension = data.get('extensions')
#
#    # Get application metadata
#    url = "http://%s:%d/applicationcatalog/application/%s" % (
#        MEC_APP_CATALOG_IP, MEC_APP_CATALOG_PORT, app_id)
#    logging.debug("Getting application metadata from url:%s" %(url))
#    headers = {}
#    update_header(headers)
#    response = requests.get(url, headers=headers)
#    data = json.loads(response.text)
#    metadata = verify_and_update_microservice_metadata(data['metadata'])
#    # Get cloudlet details from central repository based on cloudlet_id
#    url = "http://%s:%d/cloudletcatalog/cloudlet/%s" % (
#        MEC_CLOUDLET_CATALOG_IP, MEC_CLOUDLET_CATALOG_PORT, cloudlet_id)
#    logging.debug("Getting cloudlet details from central repository based on cloudlet_id from url:%s" %(url))
#    resp = requests.get(url, headers=headers)
#    data = json.loads(resp.text)
#    ip = None
#    port = None
#    for endpoint in data['endpoints']:
#        if endpoint['name'] == 'clc':
#            ip = endpoint['ip']
#            port = endpoint['port']
#
#    # Call provision api of cloudlet controller with payload as metadata and client-id
#    payload = {app_id: metadata, "clientId": client_id}
#    if extension:
#        payload['extensions'] = extension
#    headers = {'content-type': 'application/json'}
#    url = "http://%s:%s/api/v1.0/clc/%s/%s" % (
#        str(ip), str(port), developer_id, app_id)
#    logging.debug("Calling provision api of cloudlet controller with url:%s" %(url))
#    response = requests.post(url, data=json.dumps(payload), headers=headers)
#    logging.debug("Response from cloudlet controller %s" %(str(response.status_code)))
#    if response.status_code == 200:
#        return response.text
#    else:
#        return Response(response=response.reason, status=response.status_code)
#
def convert(data):
    if isinstance(data, basestring):
        return str(data)
    elif isinstance(data, collections.Mapping):
        return dict(map(convert, data.iteritems()))
    elif isinstance(data, collections.Iterable):
        return type(data)(map(convert, data))
    else:
        return data

@CMS.route('/api/v1.0/llo/sandbox/cms/<developer_id>/<app_id>', methods=['POST'])
def provision_application_sandbox(developer_id, app_id):
    logging.info("Recieved provision application sandbox with developer_id:%s and app_id:%s" %(developer_id, app_id))
    microservice = ""
    client_id = ""

    data = request.get_json()
    if data:
        microservice = data.get('microservice')
        client_id = data.get('clientId')
    if not client_id:
        client_id = ""

    if microservice and microservice.lower() == "yes":
        # Get microservice metadata
        url = "http://%s:%d/microservicecatalog/microservice/%s/" % (
            MEC_APP_CATALOG_IP, MEC_APP_CATALOG_PORT, app_id)
        logging.debug("Getting microservice metadata from url:%s" %(url))
        headers = {}
        update_header(headers)
        response = requests.get(url, headers=headers)
        data = json.loads(response.text)
        data = convert(data)
        microservice_metadata = data['metadata']

        logging.debug("Populating application metadata from microservice metadata")
        metadata = {}
        metadata["microserviceMetadata"] = []
        ms_metadata = {"microServiceName":data["microServiceName"], "tenancy":data["tenancy"], "metadata":data["metadata"]}
        if "deliveryMethod" in data:
            ms_metadata["deliveryMethod"] = data["deliveryMethod"]
        metadata["microserviceMetadata"].append(ms_metadata)
        metadata["appMetadata"] = {"microservices":[], "applicationType": data["microServiceType"].lower()}
        appmetadata_microservice = {}
        appmetadata_microservice["microServiceName"] = data["microServiceName"]
        appmetadata_microservice["exposed"] = {"networks":[], "events":[], "httpApis":[]}
        appmetadata_microservice["useAsLib"] = "N"
        appmetadata_microservice["resources"] = []
        appmetadata_microservice["subscribed"] = "N"
        if "deliveryMethod" in data:
            metadata["appMetadata"]["deliveryMethod"] = data["deliveryMethod"]

        # Get workload's list
        for workload in microservice_metadata["workloads"]:
            appmetadata_microservice_resource = {}
            appmetadata_microservice_resource["name"] = "default"
            appmetadata_microservice_resource["workloadName"] = workload["workloadName"]
            appmetadata_microservice["resources"].append(appmetadata_microservice_resource)

        # Get event's list
        for event in microservice_metadata["external"]["events"]:
            appmetadata_microservice_exposed_event = {}
            appmetadata_microservice_exposed_event["name"] = event
            appmetadata_microservice_exposed_event["exposedTo"] = ["app@client"]
            appmetadata_microservice["exposed"]["events"].append(appmetadata_microservice_exposed_event)

        # Get network's list
        for network in microservice_metadata["external"]["networks"]:
            appmetadata_microservice_exposed_network = {}
            appmetadata_microservice_exposed_network["name"] = network
            appmetadata_microservice_exposed_network["exposedTo"] = ["app@client"]
            appmetadata_microservice["exposed"]["networks"].append(appmetadata_microservice_exposed_network)

        # Get httpApi's list
        for httpApi in microservice_metadata["external"]["httpApis"]:
            appmetadata_microservice_exposed_httpApi = {}
            appmetadata_microservice_exposed_httpApi["name"] = httpApi
            appmetadata_microservice_exposed_httpApi["exposedTo"] = ["app@client"]
            appmetadata_microservice["exposed"]["httpApis"].append(appmetadata_microservice_exposed_httpApi)

        metadata["appMetadata"]["microservices"].append(appmetadata_microservice)
        logging.debug("Application metadata populated from microservice metadata")
    else:
        # Get application metadata
        url = "http://%s:%d/applicationcatalog/application/%s/" % (
            MEC_APP_CATALOG_IP, MEC_APP_CATALOG_PORT, app_id)
        logging.debug("Getting application metadata from url:%s" %(url))
        headers = {}
        update_header(headers)
        response = requests.get(url, headers=headers)
        data = json.loads(response.text)
        metadata = data['metadata']
    # Get staging cloudlet details from central repository
    central_repo_obj = CentralRepoHelper()
    cloudlets_with_env_staging = central_repo_obj.find_cloudlets_with_env(
        "staging")
    if not cloudlets_with_env_staging:
        logging.debug("No registered staging cloudlet found")
        return Response(response="No registered staging cloudlet found", status = 410)
    for key in cloudlets_with_env_staging:
        cloudlet_id = key
        ip = None
        port = None
        for endpoint in cloudlets_with_env_staging[key]['endpoints']:
            if endpoint['name'] == 'clc':
                ip = endpoint['ip']
                port = endpoint['port']
    # Call provision api of cloudlet controller with payload as metadata and client-id
    payload = {app_id: metadata, "clientId": client_id}
    headers = {'content-type': 'application/json'}
    update_header(headers)
    url = "http://%s:%s/api/v1.0/clc/%s/%s" % (
        str(ip), str(port), developer_id, app_id)
    logging.debug("Calling provision api of cloudlet controller with url:%s" %(url))
    response = requests.post(url, data=json.dumps(payload), headers=headers)
    logging.debug("Response from cloudlet controller %s" %(str(response.status_code)))
    if response.status_code == 200:
        return response.text
    else:
        return Response(response=response.reason, status=response.status_code)


@CMS.route('/api/v1.0/llo/cms/<developer_id>/<app_id>/<cloudlet_id>/<uuid>', methods=['DELETE'])
#@iam_token_validate
def terminate_application(developer_id, app_id, cloudlet_id, uuid):
    logging.info("Recieved terminate application")
    client_id = ""
    data = request.get_json()
    if data:
        client_id = data['clientId']

    # Get cloudlet details from central repository based on cloudlet_id
    url = "http://%s:%d/cloudletcatalog/cloudlet/%s" % (
        MEC_CLOUDLET_CATALOG_IP, MEC_CLOUDLET_CATALOG_PORT, cloudlet_id)
    headers = {}
    update_header(headers)
    resp = requests.get(url, headers=headers)
    data = json.loads(resp.text)
    ip = None
    port = None
    for endpoint in data['endpoints']:
        if endpoint['name'] == 'clc':
            ip = endpoint['ip']
            port = endpoint['port']

    # Call terminate api of cloudlet controller with uuid and payload as client-id
    payload = {"clientId": client_id}
    headers = {'content-type': 'application/json'}
    url = "http://%s:%s/api/v1.0/clc/%s/%s/%s" % (
        str(ip), str(port), developer_id, app_id, uuid)
    logging.debug("Sending terminate request on : %s" %(url))
    response = requests.delete(url, data=json.dumps(payload), headers=headers)
    logging.debug("Response from cloudlet : %s" %(response.status_code))
    if response.status_code == 200:
        return response.text
    else:
        return Response(status=response.status_code)


@CMS.route('/api/v1.0/llo/sandbox/cms/<developer_id>/<app_id>/<uuid>', methods=['DELETE'])
def terminate_application_sandbox(developer_id, app_id, uuid):
    logging.info("Recieved terminate application sandbox")
    client_id = ""
    data = request.get_json()
    if data:
        client_id = data['clientId']

    # Get staging cloudlet details from central repository
    central_repo_obj = CentralRepoHelper()
    cloudlets_with_env_staging = central_repo_obj.find_cloudlets_with_env(
        "staging")
    if not cloudlets_with_env_staging:
        logging.debug("No registered staging cloudlet found")
        return Response(response="No registered staging cloudlet found", status = 410)
    for key in cloudlets_with_env_staging:
        cloudlet_id = key
        ip = None
        port = None
        for endpoint in cloudlets_with_env_staging[key]['endpoints']:
            if endpoint['name'] == 'clc':
                ip = endpoint['ip']
                port = endpoint['port']

    # Call terminate api of cloudlet controller with uuid and payload as client-id
    payload = {"clientId": client_id}
    headers = {'content-type': 'application/json'}
    url = "http://%s:%s/api/v1.0/clc/%s/%s/%s" % (
        str(ip), str(port), developer_id, app_id, uuid)
    logging.debug("Sending terminate request on : %s" %(url))
    response = requests.delete(url, data=json.dumps(payload), headers=headers)
    logging.debug("Response from cloudlet : %s" %(response.status_code))
    if response.status_code == 200:
        return response.text
    else:
        return Response(status=response.status_code)


@CMS.route('/api/v1.0/llo/cms/<cloudlet_id>/images', methods=['GET'])
def list_application_images(cloudlet_id):
    # Get cloudlet details from central repository based on cloudlet_id
    url = "http://%s:%d/cloudletcatalog/cloudlet/%s" % (
        MEC_CLOUDLET_CATALOG_IP, MEC_CLOUDLET_CATALOG_PORT, cloudlet_id)
    headers = {}
    update_header(headers)
    resp = requests.get(url, headers=headers)
    data = json.loads(resp.text)
    ip = None
    port = None
    for endpoint in data['endpoints']:
        if endpoint['name'] == 'clc':
            ip = endpoint['ip']
            port = endpoint['port']

    # Get uploaded container images detail from cloudlet
    url = "http://%s:%s/api/v1.0/clc/images" % (ip, port)
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.text
    else:
        return Response(status=response.status_code)


@CMS.route('/api/v1.0/llo/cms/<cloudlet_id>/collectStats', methods=['GET'])
def collect_stats(cloudlet_id):
    uuid = request.args.get('uuid')
    if not uuid:
        uuid = ""

    # Get cloudlet details from central repository based on cloudlet_id
    url = "http://%s:%d/cloudletcatalog/cloudlet/%s" % (
        MEC_CLOUDLET_CATALOG_IP, MEC_CLOUDLET_CATALOG_PORT, cloudlet_id)
    headers = {}
    update_header(headers)
    resp = requests.get(url, headers=headers)
    data = json.loads(resp.text)
    ip = None
    port = None
    for endpoint in data['endpoints']:
        if endpoint['name'] == 'clc':
            ip = endpoint['ip']
            port = endpoint['port']

    # Get stats detail from cloudlet controller
    url = "http://%s:%s/api/v1.0/clc/collectStats?uuid=%s" % (ip, port, uuid)
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.text
    else:
        return Response(status=response.status_code)


@CMS.route('/api/v1.0/llo/cms/events', methods=['POST'])
def events():
    eventsdata = request.json['events']
    repo = eventsdata[0]['target']['repository']
    tag = None
    if 'tag' in eventsdata[0]['target']:
        tag = eventsdata[0]['target']['tag']

    # Get cloudlet details from central repository
    url = "http://%s:%d/cloudletcatalog/cloudlets" % (
        MEC_CLOUDLET_CATALOG_IP, MEC_CLOUDLET_CATALOG_PORT)
    headers = {}
    update_header(headers)
    resp = requests.get(url, headers=headers)
    data = json.loads(resp.text)
    endpoints = []
    for cloudlet in data['cloudlets']:
        endpoints.append(data['cloudlets'][cloudlet]['endpoints']['clc'])

    for endpoint in endpoints:
        # Notify cloud controller for the new image
        try:
            payload = {'repository': repo, 'tag': tag}
            headers = {'content-type': 'application/json'}
            update_header(headers)
            url = "http://%s:%s/api/v1.0/clc/notify" % (
                str(endpoint['ip']), str(endpoint['port']))
            response = requests.post(
                url, data=json.dumps(payload), headers=headers)
        except Exception as unchecked_exception:
            logging.error('Unknown exception while posting events: {}'.format(unchecked_exception))

    return Response(status=200)

if __name__ == '__main__':
    if len(sys.argv) < 5:
        print("Usage: %s <self_fqdn> <app_catalog_ip> <cloudlet_catalog_ip> <microservice_catalog_ip>" %
              sys.argv[0])
        sys.exit(1)
    
    SELF_IP = sys.argv[1]
    MEC_APP_CATALOG_IP = sys.argv[2]
    MEC_CLOUDLET_CATALOG_IP = sys.argv[3]
    MEC_MICROSERVICE_CATALOG_IP = sys.argv[4]
    
    logging.basicConfig(filename='/opt/logs/cms.log', level=logging.DEBUG,
        format='%(asctime)s %(levelname)s %(message)s')

    SELF_HOSTED_URL_PATTERN = "http://%s:%d%s" % (
        SELF_IP, MEC_CMS_PORT, SELF_HOSTED_AT)
    # Check if IAM plugin in enabled
    if IAM_PLUGGED_IN:
        init_IAM_connections()
    else:
        IAM_PLUGGED_IN = False

    CMS.run(host=SELF_IP, port=MEC_CMS_PORT, threaded=True)

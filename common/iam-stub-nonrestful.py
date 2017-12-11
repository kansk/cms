# Imports
from flask import Flask, request, Response
import requests
import json
import sys
import logging
import os
import time


IAM_PORT = 0xecc1

# IAM Stub API Version
IAM_STUB_API_VERSION = 'v1.5'

# IAM non-RESTful API endpoints
IAM_USER_GENERIC_EP = "/identity/%s/user" % (IAM_STUB_API_VERSION)
IAM_USER_EP = "/identity/%s/user/<user_id>" % (IAM_STUB_API_VERSION)
IAM_TOKEN_GEN = "/identity/%s/discoverytoken" % (IAM_STUB_API_VERSION)
IAM_TOKEN_VALIDATE = "/identity/%s/discoverytoken/<token>" % (
    IAM_STUB_API_VERSION)


iam_stub = Flask(__name__)

# As all interfaces are stubbed, no API is truly RESTful sic:(


@iam_stub.route(IAM_TOKEN_VALIDATE, methods=['GET'])
def validate_token(token):
    #     logger.info('Received request for validation of token:{}'.format(token))
    logging.info("Received request for validation of token:{}".format(token))
    # Don't authenticate or validate for now
    return Response(status=200)


# Main
logging.basicConfig(
    level=logging.INFO, format='%(asctime)-15s %(levelname)-8s %(filename)-16s %(lineno)4d %(message)s')


if __name__ == '__main__':
    iam_stub.run(host="0.0.0.0", port=IAM_PORT, threaded=True)

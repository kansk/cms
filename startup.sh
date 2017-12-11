#!/bin/sh -x
export http_proxy=http://165.225.104.34:80
export https_proxy=http://165.225.104.34:80

pip install -r /opt/llo/cms/requirements.txt

python /opt/llo/cms/cms.py 0.0.0.0 app_catalog cloudlet_catalog microservice_catalog
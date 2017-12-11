FROM tiangolo/uwsgi-nginx-flask:flask
COPY . /opt/cms
WORKDIR /opt/cms
RUN chmod +x entrypoint.sh
ENTRYPOINT ["/opt/cms/entrypoint.sh"]

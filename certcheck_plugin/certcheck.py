'''
    Dynatrace SSL Certrificate Checker Active Gate Plugin
    This plugin enhances Dynatrace synthetic monitoring by adding a SSL certificate validation that checks for the expiry date of certificates

    The plugin works by executing on an Active Gate, fetching all (or tagged) HTTP synthetic monitors
    from the environment and then validating their certificates.
    If a certificate expires within the given amount of days the plugin will post an error event to Dynatrace.

'''
#!/usr/bin/env python
__author__ = "Reinhard Weber"
__copyright__ = "Copyright 2021, 360 Performance GmbH"
__credits__ = ["Reinhard Weber"]
__license__ = "GPL"
__version__ = "1.0"
__maintainer__ = "Reinhard Weber"
__email__ = "r.weber@360performance.net"
__status__ = "Production"

from ruxit.api.base_plugin import RemoteBasePlugin
from ruxit.api.exceptions import ConfigException
import requests, urllib3, json
import logging,sys,traceback
from urllib.parse import urlencode, urlparse
from datetime import datetime, timedelta

from OpenSSL import SSL
from cryptography import x509
from cryptography.x509.oid import NameOID
import idna

from socket import socket
from collections import namedtuple

HostInfo = namedtuple(field_names='cert hostname peername', typename='HostInfo')
datefmt = "%Y-%m-%d %H:%M:%S"

logger = logging.getLogger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CertificateCheckPlugin(RemoteBasePlugin):

    def initialize(self, **kwargs):
        logger.info("Config: %s", self.config)
        self.minduration = self.config["minduration"]
        self.tenant = self.config["tenantUUID"]
        self.apitoken = self.config["apitoken"]
        self.tag = self.config["tag"]
        self.interval = self.config["interval"]
        self.server = "https://localhost:9999/e/"+self.tenant   # this is an active gate plugin so it can call the DT API on localhost
        self.problemtimeout = 15


    def query(self, **kwargs):
        config = kwargs['config']
        group_name = "SSL Certificate Hosts"
        group = self.topology_builder.create_group(group_name, group_name)

        # determine if we should run the checks based on selected interval
        time_minute = datetime.now().minute
        time_hour = datetime.now().hour
        if "hour" in self.interval:
            hour = int(self.interval.strip().split()[0])
            run = (time_hour%hour == 0) and time_minute == 0
            self.problemtimeout = hour*60*2
        if "minute" in self.interval:
            minute = int(self.interval.strip().split()[0])
            run = (time_minute%minute == 0)
            self.problemtimeout = minute*2
        
        logger.info("Set to run every {}, it is now {:02d}:{:02d}. Check will{}run!".format(self.interval,time_hour, time_minute, " " if run else " not "))
        
        if run:
            # Get Hosts from Already Configured Synthetic Monitors of this environment
            hosts = self.getSSLCheckHosts(self.getSyntheticMonitors())
            #logger.info(hosts)
            self.getCertExpiry(hosts)


    def getSyntheticMonitors(self):
        apiurl = "/api/v1/synthetic/monitors"
        parameters = {"tag":self.tag, "enabled":"true"}
        query = "?"+urlencode(parameters)
        headers = {"Authorization": "Api-Token {}".format(self.apitoken)}
        url = self.server + apiurl + query

        monitors = {}
        try:
            response = requests.get(url, headers=headers, verify=False)
            result = response.json()
            if response.status_code == requests.codes.ok:
                for monitor in result["monitors"]:
                    monitors.update({monitor["entityId"]:monitor["name"]})
            else:
                logger.error("Getting monitors returned {}: {}".format(m_id,response.status_code,result))
        except:
            logger.error("Error while trying to get synthetic monitors for {}::{}".format(clusterid,tenantid))

        #logger.info(monitors)
        return monitors

    def getSSLCheckHosts(self, monitors):
        apiurl = "/api/v1/synthetic/monitors/:id"
        #parameters = {"clusterid":clusterid}
        #query = "?"+urlencode(parameters)
        headers = {"Authorization": "Api-Token {}".format(self.apitoken)}
        url = self.server + apiurl #+ query

        hosts = {}
        session = requests.session()
        #session.auth = (apiuser, apipwd)
        session.verify = False
        session.headers = headers
        for m_id,m_name in monitors.items():
            try:
                m_url = url.replace(':id',m_id)
                response = session.get(m_url)
                result = response.json()
                if response.status_code == requests.codes.ok:
                    m_requests = result["script"]
                    if result["type"] == "HTTP":
                        request_key = "requests"
                    if result["type"] == "BROWSER":
                        request_key = "events"
                    
                    for req in m_requests[request_key]:
                        parsed = urlparse(req["url"])
                        if parsed.scheme == "https":
                            hosts.update({"{}://{}{}".format(parsed.scheme, parsed.hostname, "" if not parsed.port else ":"+str(parsed.port)) : m_id})
                else:
                    logger.error("Getting monitor details for {} returned {}: {}".format(m_id,response.status_code,result))
            except:
                logger.error("Error while trying to get synthetic hosts") 
        
        return hosts

    def get_certificate(self, hostname, port):
        hostname_idna = idna.encode(hostname)
        sock = socket()

        try:
            #sock.settimeout(30.0)
            sock.connect((hostname, port))
            peername = sock.getpeername()
        except Exception as e:
            logger.error("Failed to connect to {}:{} - {}".format(hostname, port, e))
            return None

        ctx = SSL.Context(SSL.SSLv23_METHOD)
        ctx.check_hostname = False
        ctx.verify_mode = SSL.VERIFY_NONE

        sock_ssl = SSL.Connection(ctx, sock)
        sock_ssl.set_connect_state()
        sock_ssl.set_tlsext_host_name(hostname_idna)
        sock_ssl.do_handshake()
        cert = sock_ssl.get_peer_certificate()
        crypto_cert = cert.to_cryptography()
        sock_ssl.close()
        sock.close()

        return HostInfo(cert=crypto_cert, peername=peername, hostname=hostname)

    def get_alt_names(self, cert):
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            return ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            return None

    def get_common_name(self, cert):
        try:
            names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            return names[0].value
        except x509.ExtensionNotFound:
            return None

    def get_issuer(self, cert):
        try:
            names = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            return names[0].value
        except x509.ExtensionNotFound:
            return None

    def getCertExpiry(self, hosts):
        for host, monitor_id in hosts.items():
            parsed = urlparse(host)
            hostinfo = self.get_certificate(parsed.hostname, int(parsed.port) if parsed.port else 443)

            if hostinfo is not None:
                notafter=hostinfo.cert.not_valid_after
                now = datetime.now()
                expires = (notafter - now).days
                logger.info("Certificate for {} (MonitorID: {}) expires in {} days: {}".format(parsed.hostname, monitor_id, expires, "ERROR" if expires < self.minduration else "OK"))
                
                if expires < self.minduration:
                    self.reportCertExpiryEvent(hostinfo, expires, monitor_id)

    def reportCertExpiryEvent(self, hostinfo, expires, monitor_id):
        start = datetime.now()
        end = start + timedelta(minutes=5)
        notbefore = hostinfo.cert.not_valid_before
        notafter = hostinfo.cert.not_valid_after
        event = {
                    "eventType": "ERROR_EVENT",
                    "start": int(datetime.timestamp(start)*1000),
                    "end": int(datetime.timestamp(end)*1000),
                    "timeoutMinutes": self.problemtimeout,
                    "title": "SSL Certificate about to expire",
                    "description": "The SSL certificate for {} will expire in {} days!".format(hostinfo.hostname, expires),
                    "attachRules": { "entityIds": [ monitor_id ] },
                    "source": "Certificate Checker Active Gate Plugin",
                    "customProperties": {
                        "CommonName": self.get_common_name(hostinfo.cert),
                        "Issuer": self.get_issuer(hostinfo.cert),
                        "NotBefore": notbefore.strftime(datefmt),
                        "NotAfter": notafter.strftime(datefmt)
                    },
                    "allowDavismerge": "false"
                }
        
        apiurl = "/api/v1/events"
        headers = {"Content-type": "application/json", "Authorization": "Api-Token {}".format(self.apitoken)}
        url = self.server + apiurl

        data = json.dumps(event)
        try:
            response = requests.post(url, json=event, headers=headers, verify=False)
            logger.info(response.json())
        except:
            logger.error("There was a problem posting error event to Dynatrace!")

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
from ruxit.select_plugins import BaseActivationContext, selectors
import requests, urllib3, json
import logging, sys, traceback, select
from urllib.parse import urlencode, urlparse
from datetime import datetime, timedelta, timezone

from OpenSSL import SSL
from cryptography import x509
from cryptography.x509.oid import NameOID
import idna

from socket import socket, AF_INET, SOCK_STREAM
from collections import namedtuple

HostInfo = namedtuple(field_names='cert hostname peername', typename='HostInfo')
datefmt = "%Y-%m-%d %H:%M:%S"
SOURCE = "Certificate Checker AG Plugin"

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
        self.proxy_addr = self.config["proxy_addr"]
        self.proxy_port = self.config["proxy_port"]
        self.problemtimeout = 120
        self.refreshcheck = 5
        self.source = "{} ({})".format(SOURCE,self.activation.endpoint_name)


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
        if "minute" in self.interval:
            minute = int(self.interval.strip().split()[0])
            run = (time_minute%minute == 0)
        
        logger.info("Set to run every {}, it is now {:02d}:{:02d}. Check will{}run!".format(self.interval,time_hour, time_minute, " " if run else " not "))
        
        # get monitors with openevents that are about to timeout, ensure refresh in time or proactively close if no reason to keep them open
        # this also ensures clearance of problems that are fixed
        refreshmonitors = {}
        if (time_minute%self.refreshcheck == 0 and not run):
            refreshmonitors = self.getMonitorsWithOpenEvents()
            # check those with open problems if a clearance would be possible (check more frequently than others)
            hosts = self.getSSLCheckHosts(refreshmonitors)
            logger.info("Refreshing open problems for: {}".format(list(hosts.keys())))
            self.getCertExpiry(hosts, True)

        # regular run with all monitors at defined interval
        monitors = {}
        if run:
            monitors = self.getSyntheticMonitors()
            hosts = self.getSSLCheckHosts(monitors)
            self.getCertExpiry(hosts, False)

    def getMonitorsWithOpenEvents(self):
        # get all open events created by this plugin and check them again.
        # this is to avoid that the events expire if a longer execution interval than 120min (maximum event duration) is selected
        apiurl = "/api/v1/events"
        parameters = {"eventType": "ERROR_EVENT", "relativeTime": "10mins"}
        headers = {"Authorization": "Api-Token {}".format(self.apitoken)}
        url = self.server + apiurl

        monitors = {}
        try:
            response = requests.get(url, params=parameters, headers=headers, verify=False)
            result = response.json()
            if response.status_code == requests.codes.ok:
                for event in result["events"]:
                    if "OPEN" in event["eventStatus"] and self.source in event["source"]:
                        start_TS =  int(event["startTime"])
                        now = datetime.now()
                        now_TS = int(datetime.timestamp(now)*1000)
                        diff_min = int((now_TS - start_TS)/1000/60)
                        logger.info("A problem for {} is already open for {} minutes".format(event["entityName"], diff_min))

                        #if diff_min > self.problemtimeout - self.refreshcheck*2:
                        monitors.update({event["entityId"]:event["entityName"]})
            else:
                logger.error("Getting events returned {}: {}".format(response.status_code,result))
        except Exception as e:
            logger.error("Error while getting open events {}: {}".format(url, e))

        return monitors


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
                logger.error("Getting monitors returned {}: {}".format(response.status_code,result))
        except:
            logger.error("Error while trying to get synthetic monitors from {}".format(url))

        return monitors

    def getSSLCheckHosts(self, monitors):
        apiurl = "/api/v1/synthetic/monitors/:id"
        headers = {"Authorization": "Api-Token {}".format(self.apitoken)}
        url = self.server + apiurl

        hosts = {}
        session = requests.session()
        session.verify = False
        session.headers = headers
        for m_id,m_timeout in monitors.items():
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
        connect_addr = (hostname, port)
        connect = ""
        if self.proxy_addr:
            connect_addr = (self.proxy_addr, self.proxy_port)
            connect = "CONNECT {}:{} HTTP/1.0\r\nConnection: close\r\n\r\n".format(hostname, port)

        hostname_idna = idna.encode(hostname)
        sock = socket(AF_INET, SOCK_STREAM)

        try:
            sock.settimeout(3.0)
            sock.connect(connect_addr)
            if connect:             #proxied SSL connection
                sock.send(connect.encode('utf-8'))
                data = sock.recv(4096)
                if "200" not in str(data):
                    raise Exception("Proxy CONNECT to {} via proxy {} failed: {}".format(hostname, self.proxy, str(data)))

            peername = sock.getpeername()
        except Exception as e:
            logger.error("Failed to connect to {}:{} - {}".format(hostname, port, e))
            return None

        ctx = SSL.Context(SSL.TLSv1_2_METHOD)
        '''
        SSL.SSLv2_METHOD
        SSL.SSLv3_METHOD
        SSL.SSLv23_METHOD
        SSL.TLSv1_METHOD
        SSL.TLSv1_1_METHOD
        SSL.TLSv1_2_METHOD
        '''
        ctx.check_hostname = False
        ctx.verify_mode = SSL.VERIFY_NONE

        sock.setblocking(1)
        sock_ssl = SSL.Connection(ctx, sock)
        sock_ssl.set_connect_state()
        sock_ssl.set_tlsext_host_name(hostname_idna)
        try:
            sock_ssl.do_handshake()
        except Exception as e:
            logger.error("SSL Handshake error when connecting to {}:{} (using proxy: {}): {}. Please make sure the host is reachable and supports TLSv1.2!".format(hostname, port, "true" if connect else "false", e))
            return None

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

    def getCertExpiry(self, hosts, clear):
        for host, monitor_id in hosts.items():
            parsed = urlparse(host)
            hostinfo = self.get_certificate(parsed.hostname, int(parsed.port) if parsed.port else 443)

            if hostinfo is not None:
                notafter=hostinfo.cert.not_valid_after
                now = datetime.now()
                expires = (notafter - now).days
                logger.info("Certificate for {} (MonitorID: {}) expires in {} days: {}".format(parsed.hostname, monitor_id, expires, "ERROR" if expires < self.minduration else "OK"))
                
                if expires < self.minduration:
                    self.reportCertExpiryEvent(hostinfo, expires, monitor_id, False)
                else:
                    if clear:
                        self.reportCertExpiryEvent(hostinfo, expires, monitor_id, True)
  
    def reportCertExpiryEvent(self, hostinfo, expires, monitor_id, clear):
        notbefore = hostinfo.cert.not_valid_before
        notafter = hostinfo.cert.not_valid_after

        timeout = 1 if clear else self.problemtimeout
        event = {
                    "eventType": "ERROR_EVENT",
                    "timeoutMinutes": timeout,
                    "title": "SSL Certificate about to expire",
                    "description": "The SSL certificate for {} will expire in {} days!".format(hostinfo.hostname, expires),
                    "attachRules": { "entityIds": [ monitor_id ] },
                    "source": self.source,
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
            logger.info("{} problem with timeout: {}".format("Closeing existing" if clear else "Refreshing/opening new", timeout))
            #logger.info(response.json())
        except:
            logger.error("There was a problem posting error event to Dynatrace!")

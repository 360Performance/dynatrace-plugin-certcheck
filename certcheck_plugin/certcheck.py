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
import _thread
import time
from multiprocessing.pool import ThreadPool

from OpenSSL import SSL
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509.oid import ExtensionOID
import idna

from socket import socket, AF_INET, SOCK_STREAM
from collections import namedtuple

HostInfo = namedtuple(field_names='cert hostname peername tlsversion cipher', typename='HostInfo')
CheckInfo = namedtuple(field_names='url id name expire proxy', typename='CheckInfo')
datefmt = "%Y-%m-%d %H:%M:%S"
SOURCE = "Certificate Checker AG Plugin (by 360performance.net)"
PROBLEM_TITLE = "SSL Certificate about to expire"
INFO_TITLE = "TLS Version outdated"
TAG_PROXY="SSLCheckProxy"
TAG_EXPIRE="SSLCheckExpire"

logger = logging.getLogger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CertificateCheckPlugin(RemoteBasePlugin):

    def initialize(self, **kwargs):
        logger.info("Config: %s", self.config)
        self.minduration = self.config["minduration"]
        self.tenant = self.config["tenantUUID"]
        self.apitoken = self.config["apitoken"]
        self.tag = self.config["tag"]
        self.consider_disabled = self.config["consider_disabled"]
        self.reportmetric = self.config["reportmetric"]
        self.interval = self.config["interval"]
        self.server = "https://localhost:9999/e/"+self.tenant   # this is an active gate plugin so it can call the DT API on localhost
        self.proxy_addr = self.config["proxy_addr"]
        self.proxy_port = self.config["proxy_port"]
        self.internal_ca = self.config["internal_ca"]
        self.problemtimeout = 30
        self.refreshcheck = 5
        self.source = "{} (Endpoint config: {})".format(SOURCE,self.activation.endpoint_name)
        self.start = time.time()
        logger.setLevel(self.config.get("log_level"))
        self.sockettimeout = float(self.config["socket_timeout"])


    def query(self, **kwargs):
        config = kwargs['config']
        group_name = "SSL Certificate Hosts"
        group = self.topology_builder.create_group(group_name, group_name)
        logger.debug("Starting new query.")
        # determine if we should run the checks based on selected interval
        time_minute = datetime.now().minute
        time_hour = datetime.now().hour
        if "hour" in self.interval:
            hour = int(self.interval.strip().split()[0])
            run = (time_hour%hour == 0) and time_minute == 0
        if "minute" in self.interval:
            minute = int(self.interval.strip().split()[0])
            run = (time_minute%minute == 0)
        
        # get monitors with openevents that are about to timeout, ensure refresh in time or proactively close if no reason to keep them open
        # this also ensures clearance of problems that are fixed
        refreshmonitors = {}
        if (time_minute%self.refreshcheck == 0 and not run):
            refreshmonitors = self.getMonitorsWithOpenEvents()
            logger.info("There are {} synthetic monitors with open certificate problems we need to check/refresh".format(len(refreshmonitors)))
            # check those with open problems if a clearance would be possible (check more frequently than others)
            hosts = self.getSSLCheckHosts(refreshmonitors)
            logger.info("Refreshing open problems for: {}".format([h.url for h in hosts]))
            self.getCertExpiry(hosts, True)

        # regular run with all monitors at defined interval
        monitors = {}
        if run:
            logger.debug("In line 104: run")
            monitors = self.getSyntheticMonitors()
            logger.info("There are {} synthetic monitors to perform SSL certificate checks for".format(len(monitors)))

            pool = ThreadPool(processes = 10)            
            for m_id,m_name in monitors.items():
                logger.info("Checking SSL certificate for {} ({})".format(m_id,m_name))
                #m = {}
                #m.update({m_id:m_name})
                logger.debug("In line 110: starting async ssl checks.")
                pool.apply_async(self.performSSLCheck, args=({m_id:m_name},))
            pool.close()
            pool.join()
            logger.debug("In line 117: end of async ssl checks.")
            
            # Max polling time is 50 seconds
            process_alive = 0
            while time.time() - self.start < 50:
                logger.debug("In line 119: checking for alive threads at 50s.")
                process_alive = 0
                for process in pool._pool:
                    if process.is_alive():
                        process_alive += 1
                if process_alive == 0:
                    logger.info('All processes have finished, exiting poll loop')
                    break
                time.sleep(1)
            
            # If we get to this point, a process was flagged alive and it's been more than 50 seconds, then terminate it
            # Otherwise, if process_alive was not set above, then no process should be alive at this point and no need to terminate
            if process_alive > 0:
                logger.debug("In line 132: before terminating threads.")
                pool.terminate()
                pool.join()
                logger.info(str(process_alive) + ' processes are alive. Terminating before finishing polling cycle')

    def performSSLCheck(self,monitors):
        logger.info("Performing SSL check for {}".format(monitors))
        hosts = self.getSSLCheckHosts(monitors)
        logger.info("Checking certificate on host: {}".format(hosts))
        self.getCertExpiry(hosts, False)


    # ingest custom metrics to Dynatrace (using etrics API as it provides more flexibility)
    def ingestMetrics(self, data):
        apiurl = "/api/v2/metrics/ingest"
        headers = {"Authorization": "Api-Token {}".format(self.apitoken), "Content-Type": "text/plain"}
        url = self.server + apiurl
        for line in data:
            try:
                response = requests.post(url, headers=headers, verify=False, data=line)
                if response.status_code != 202:
                    logger.info("Ingesting metrics failed: {} {}".format("\n".join(response, line)))
            except:
                logger.error("Metric ingestion failed: {}".format(response, line))

    def isProblemOpen(self,entityId):
        apiurl = "/api/v2/problems"
        parameters = {"problemSelector": "impactedEntities(\"{}\"),status(\"OPEN\"),text(\"{}\")".format(entityId, PROBLEM_TITLE[0:30]), "from": "now-{}m".format(self.refreshcheck)}
        headers = {"Authorization": "Api-Token {}".format(self.apitoken)}
        url = self.server + apiurl
        try:
            logger.info("Getting monitors with open problems: {} {}".format(url,parameters))
            response = requests.get(url, params=parameters, headers=headers, verify=False)
            result = response.json()
            if response.ok:
                if len(result["problems"]) > 0:
                    logger.info("{} open problems for {}".format(len(result["problems"]),entityId))
                    return True
                else:
                    return False
            else:
                logger.error("Checking problems for monitor {} failed - Response: {}".format(entityId,response.status_code))
                logger.error("{}".format(result))
        except Exception as e:
            logger.error("Error while getting open problem status {}: {}".format(url, e))


    def getEventForMonitor(self, monitor_id):
        #in case of timeout of get_certificate we need to fetch an existing event and extend it's runtime
        apiurl = "/api/v2/events"
        parameters = {"eventSelector": "eventType(\"ERROR_EVENT\"),status(\"OPEN\"),property.dt.event.title(\"{}\"),property.dt.event.source(\"{}\",entityId(\"{}\")".format(PROBLEM_TITLE,self.source,monitor_id),"from": "now-{}m".format(self.refreshcheck)}
        headers = {"Authorization": "Api-Token {}".format(self.apitoken)}
        url = self.server + apiurl
        try:
            logger.debug("Getting event for monitor: {} {}".format(url,parameters))
            response = requests.get(url, params=parameters, headers=headers, verify=False)
            result = response.json()
            logger.debug(f"Event found: {result}")
            if response.ok:
                if len(result["events"]) != 1:
                    logger.debug(f"Error while getting event for monitor {monitor_id}!")
                else:
                    return result["events"][0]
        except Exception as e:
            logger.error("Error while getting event for monitor {}: {}".format(url, e))
        return None



    def getMonitorsWithOpenEvents(self):
        # get all open events created by this plugin and check them again.
        # this is to avoid that the events expire if a longer execution interval than 120min (maximum event duration) is selected
        # if a problem gets manually closed we need to make sure that the event also expires so that eventually a new problem can be opened.
        # so we check the open problem AND the event if no open problem exists we do not refresh the event but let it expire, once it expires a new problem will be opened

        apiurl = "/api/v2/events"
        parameters = {"eventSelector": "eventType(\"ERROR_EVENT\"),status(\"OPEN\"),property.dt.event.title(\"{}\"),property.dt.event.source(\"{}\")".format(PROBLEM_TITLE,self.source),"from": "now-{}m".format(self.refreshcheck)}
        headers = {"Authorization": "Api-Token {}".format(self.apitoken)}
        url = self.server + apiurl

        monitors = {}
        try:
            logger.info("Getting monitors with open events: {} {}".format(url,parameters))
            response = requests.get(url, params=parameters, headers=headers, verify=False)
            result = response.json()
            if response.ok:
                for event in result["events"]:
                    start_TS =  int(event["startTime"])
                    now = datetime.now()
                    now_TS = int(datetime.timestamp(now)*1000)
                    diff_min = int((now_TS - start_TS)/1000/60)

                    # for every open event there should also be an open problem (if not then it has been closed manually and we should reopen it)
                    entityId = event["entityId"]["entityId"]["id"]
                    if self.isProblemOpen(entityId):
                        logger.info("A problem for {} is already open for {} minutes".format(event["entityId"]["name"], diff_min))
                        monitors.update({event["entityId"]["entityId"]["id"]:event["entityId"]["name"]})
            else:
                logger.error("Getting open events failed - Response: ".format(response.status_code))
                logger.error("{}".format(result))
        except Exception as e:
            logger.error("Error while getting open events {}: {}".format(url, e))

        return monitors

    def getSyntheticMonitors(self):
        apiurl = "/api/v1/synthetic/monitors"
        parameters = {"tag":self.tag, "enabled":"true"}
        if self.consider_disabled:
            del parameters["enabled"]
        query = "?"+urlencode(parameters)
        headers = {"Authorization": "Api-Token {}".format(self.apitoken)}
        url = self.server + apiurl + query

        monitors = {}
        inactiveMonitors = {} # identify monitors that have a old last seen timestamp
        try:
            response = requests.get(url, headers=headers, verify=False)
            result = response.json()
            if response.ok:
                for monitor in result["monitors"]:
                    monitors.update({monitor["entityId"]:monitor["name"]})
            else:
                logger.error("Getting monitors failed - Response: ".format(response.status_code))
                logger.error("{}".format(result))
        except:
            logger.error("Error while trying to get synthetic monitors from {}".format(url))

        return monitors

    def getSSLCheckHosts(self, monitors):
        apiurl = "/api/v1/synthetic/monitors/:id"
        headers = {"Content-type": "application/json", "Authorization": "Api-Token {}".format(self.apitoken)}
        url = self.server + apiurl

        hosts = []
        session = requests.session()
        session.verify = False
        session.headers = headers
        logger.debug("In line 250: getting SSLCheckHosts.")
        for m_id,m_timeout in monitors.items():
            try:
                m_url = url.replace(':id',m_id)
                response = session.get(m_url)
                result = response.json()
                if response.ok:
                    # write back the monitor 1:1, this ensures it's entity is active and events can be posted to it
                    # simple, dirty workaround for DT limitation and without having to trigger the ondemandexecution (consumes DEM) and without having to trigger the ondemandexecution (consumes DEM)
                    putresp = session.put(m_url, json=result)
                    logger.info("Touching monitor {} to avoid entity expiration of 24 hours - Result: {}".format(m_id,putresp.status_code))
                    if not putresp.ok:
                        logger.info(putresp.json())

                    m_requests = result["script"]
                    if result["type"] == "HTTP":
                        request_key = "requests"
                    if result["type"] == "BROWSER":
                        request_key = "events"

                    m_name = result["name"]

                    #check for special config tags
                    proxy = None 
                    if self.proxy_addr and self.proxy_port > 0:
                        proxy = f'{self.proxy_addr}:{self.proxy_port}'
                        
                    expire = None
                    for tag in result["tags"]:
                        if tag["key"] == TAG_PROXY:
                            proxy = tag["value"] if "value" in tag else None
                        if tag["key"] == TAG_EXPIRE and "value" in tag:
                            expire = tag["value"]
                    
                    for req in m_requests[request_key]:
                        parsed = urlparse(req["url"])
                        if parsed.scheme == "https":
                            #hosts.update({"{}://{}{}".format(parsed.scheme, parsed.hostname, "" if not parsed.port else ":"+str(parsed.port)) : m_id})
                            hosts.append(CheckInfo(url="{}://{}{}".format(parsed.scheme, parsed.hostname, "" if not parsed.port else ":"+str(parsed.port)), 
                                                   id=m_id,
                                                   name=m_name,
                                                   expire=expire,
                                                   proxy=proxy
                                                  ))
                            break
                else:
                    logger.error("Getting monitor details for {} returned {}: {}".format(m_id,response.status_code,result))
            except:
                logger.error("Error while trying to get synthetic hosts: {}".format(traceback.format_exc())) 
        
        return hosts

    def get_certificate(self, hostname, port, proxy):
        connect_addr = (hostname, port)
        connect = None
        #if self.proxy_addr:
        #    connect_addr = (self.proxy_addr, self.proxy_port)
        #    connect = "CONNECT {}:{} HTTP/1.0\r\nConnection: close\r\n\r\n".format(hostname, port)
        if proxy:
            parsed = urlparse("//"+proxy)
            connect_addr = (parsed.hostname, parsed.port)
            connect = "CONNECT {}:{} HTTP/1.0\r\nConnection: close\r\n\r\n".format(hostname, port)

        hostname_idna = idna.encode(hostname)
        sock = socket(AF_INET, SOCK_STREAM)
        logger.debug(f"In line 315: getting certificate for {hostname}.")

        try:
            sock.settimeout(self.sockettimeout)
            sock.connect(connect_addr)
            if connect:             #proxied SSL connection
                sock.send(connect.encode('utf-8'))
                data = sock.recv(4096)
                if "200" not in str(data):
                    raise Exception("Proxy CONNECT to {} via proxy {} failed: {}".format(hostname, connect_addr, str(data)))

            peername = sock.getpeername()
        except Exception as e:
            logger.error("Failed to connect to {}:{} {} - {}".format(hostname, port, "via proxy: {}".format(connect_addr) if connect else "", e))
            return None

        ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
        ctx.check_hostname = False
        ctx.verify_mode = SSL.VERIFY_NONE
        ctx.set_options(0x4)
        #ctx.set_options(SSL.OP_NO_TLSv1_3)

        sock.setblocking(1)
        sock_ssl = SSL.Connection(ctx, sock)
        sock_ssl.set_connect_state()
        sock_ssl.set_tlsext_host_name(hostname_idna)
        logger.debug("In line 341: starting ssl handshake.")
        try:
            sock_ssl.do_handshake()
        except Exception as e:
            logger.error("SSL Handshake error when connecting to {}:{} (using proxy: {}): {}. Please make sure the host is reachable and supports TLSv1.2!".format(hostname, port, "true" if connect else "false", e))
            return None

        cert = sock_ssl.get_peer_certificate()
        protocol = sock_ssl.get_protocol_version()
        protocol_name = sock_ssl.get_protocol_version_name()
        cipher_version = sock_ssl.get_cipher_version()
        cipher_name = sock_ssl.get_cipher_name()

        logger.info(f"TLS connection to {hostname} with version: {protocol_name}, cipher: {cipher_name}:{cipher_version}")

        crypto_cert = cert.to_cryptography()
        sock_ssl.close()
        sock.close()

        return HostInfo(cert=crypto_cert, peername=peername, hostname=hostname, tlsversion=(protocol,protocol_name), cipher=(cipher_version,cipher_name))

    def get_alt_names(self, cert):
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            return ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            return []

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

    def get_extension(self, cert, oid):
        try:
            return cert.extensions.get_extension_for_oid(oid)
        except x509.ExtensionNotFound:
            return None

    def validateHostname(self, hostname, cert):
        if hostname.casefold() == self.get_common_name(cert):
            return True
        
        for altname in self.get_alt_names(cert):
            if hostname.endswith(altname.split('*')[-1]):
                return True
        
        return False

    def getCertExpiry(self, hosts, clear):
        metricdata = []
        for host in hosts:
            logger.debug("In line 402: getCertExpiry.")
            parsed = urlparse(host.url)
            hostinfo = self.get_certificate(parsed.hostname, int(parsed.port) if parsed.port else 443, host.proxy)
            logger.debug("In line 429: after get_certificate")
            if hostinfo is not None:
                logger.debug(f"In line 431: hostinfo is: {hostinfo}")
                notafter=hostinfo.cert.not_valid_after
                now = datetime.now()
                expires = (notafter - now).days
                expire = int(host.expire) if host.expire else self.minduration
                logger.info("Certificate for {} (MonitorID: {}) expires in {} days: {}".format(parsed.hostname, host.id, expires, "ERROR" if expires < expire else "OK"))
                
                if expires < expire:
                    self.reportCertExpiryEvent(hostinfo, expires, host.id, False)
                else:
                    if clear:
                        self.reportCertExpiryEvent(hostinfo, expires, host.id, True)
                
                # assign tag to monitor with CA info
                self.addCATagToMonitor(hostinfo, host.id)
                
                metricdata.append("threesixty-perf.certificates.daystoexpiry,hostname=\"{}\",monitorname=\"{}\" {:.2f}".format(parsed.hostname,host.name,expires))

                # report a problem if the TLS version used by the checked host is considerd insecure
                if hostinfo.tlsversion[0] < SSL.TLS1_2_VERSION:
                    self.reportTLSVersionWarning(hostinfo, host.id)
                    
                # also perform a hostname check against the certificate
                # not performing this on the SSL connection level to allow the use of self-signed certificates without the need to import the CA to the active gate
                if not self.validateHostname(parsed.hostname, hostinfo.cert):
                    self.reportHostnameMismatchEvent(hostinfo, host.id)
            else:       # SSL Connection failed for other reason
                logger.debug(f"In line 458: hostinfo is: {hostinfo}")
                # if timeout in get_certificate we still extend the event to avoid re-opening of problems 
                event = self.getEventForMonitor(host)
                event["timeout"] = self.problemtimeout
                apiurl = "/api/v2/events/ingest"
                headers = {"Content-type": "application/json", "Authorization": f'Api-Token {self.apitoken}'}
                url = self.server + apiurl
                try:
                    response = requests.post(url, json=event, headers=headers, verify=False)
                    logger.info("{} problem with timeout: {} - Response: {}".format("Closing existing" if clear else "Refreshing/opening new", self.problemtimeout, response.status_code))
                except:
                    logger.error("There was a problem posting error event to Dynatrace: ".format(traceback.format_exc()))



        
        #optionally report days left to expire as metric        
        if self.reportmetric:
            self.ingestMetrics(metricdata)
    
    def triggerOnDemandExecution(self,monitor_id):
        logger.debug("In line 441: trigger on demand execution.")
        execution = {
                        "processingMode": "DISABLE_PROBLEM_DETECTION",
                        "failOnPerformanceIssue": "false",
                        "stopOnProblem": "false",
                        "monitors": [
                            {
                                "monitorId": "{}".format(monitor_id),
                                "locations": []
                            }
                        ]
                    }

        apiurl = "/api/v2/synthetic/executions/batch"
        headers = {"Content-type": "application/json", "Authorization": "Api-Token {}".format(self.apitoken)}
        url = self.server + apiurl

        data = json.dumps(execution)
        try:
            response = requests.post(url, json=execution, headers=headers, verify=False)
            logger.info("Trigger on-demand execution of monitor: {} (to ensure Dynatrace considers it active)".format(monitor_id, response.status_code))

            # reading on-demand trigger response
            if response.ok:
                result = response.json()
                if result["triggeringProblemsCount"] == 0:
                    executionId = result["triggered"][0]["executions"][0]["executionId"]
                    logger.info("On-demand execution id: {}".format(executionId))
                else:
                    logger.info("On-demand execution failed: {}".format(result["triggeringProblemDetails"]))
                    # in case monitors are disabled, maybe try to enable them automatically and set execution frequency to 0
        except:
            logger.error("There was a problem triggering on-demand execution".format(traceback.format_exc()))


    def reportTLSVersionWarning(self, hostinfo, monitor_id):
        logger.debug("In line 516: reportTLSVersionWarning")
        event = {
                    "eventType": "CUSTOM_INFO",
                    "timeout": self.problemtimeout,
                    "title": f'{INFO_TITLE}',
                    "entitySelector": f'entityId({monitor_id})', 
                    "properties": {
                        "dt.event.description": f'The protocol version ({hostinfo.tlsversion[1]}) for {hostinfo.hostname} is considered insecure',
                        "dt.event.source": self.source,
                        "dt.event.allow_davis_merge": False
                    },
                }
        
        apiurl = "/api/v2/events/ingest"
        headers = {"Content-type": "application/json", "Authorization": f'Api-Token {self.apitoken}'}
        url = self.server + apiurl
        try:
            response = requests.post(url, json=event, headers=headers, verify=False)
            logger.info("Adding protocol version info event to monitor: {} - Response: {}".format(response.status_code))
        except:
            logger.error("There was a problem posting info event to Dynatrace: ".format(traceback.format_exc()))


    def reportHostnameMismatchEvent(self, hostinfo, monitor_id):
        pass

    # tags a monitor with CA information, so that it is distinguishable if the cert is maintained internally/externally
    def addCATagToMonitor(self, hostinfo, monitor_id):
        ca = self.get_common_name(hostinfo.cert)
        cert_type = "internal" if self.internal_ca in ca else "external"
        tags = { 
                    "tags": [
                        {
                            "key": "certType",
                            "value": f'{cert_type}'
                        }
                    ]
                }
        
        apiurl = f"/api/v2/tags?entitySelector=entityId({monitor_id})"
        headers = {"Content-type": "application/json", "Authorization": f'Api-Token {self.apitoken}'}
        url = self.server + apiurl

        try:
            logger.debug(f"tag url: {url}")
            response = requests.post(url, json=tags, headers=headers, verify=False)
            logger.info("Tagging monitor for {} with certType: {} - Response: {}".format(hostinfo.hostname, cert_type, response.text))
        except:
            logger.error("There was a problem tagging the monitor with CA info: ".format(traceback.format_exc()))

    def reportCertExpiryEvent(self, hostinfo, expires, monitor_id, clear):

        # In case we are working with a disabled synthetic monitor, Dynatrace would consider the monitor as inactive and would not allow
        # adding events to it. See https://github.com/360Performance/dynatrace-plugin-certcheck/issues/13
        # To avoid this behavior we need to set the monitor into an active state. We can do so by leveraging the on-demand executions
        #self.triggerOnDemandExecution(monitor_id)

        notbefore = hostinfo.cert.not_valid_before
        notafter = hostinfo.cert.not_valid_after

        validHostname = self.validateHostname(hostinfo.hostname, hostinfo.cert)

        timeout = 1 if clear else self.problemtimeout
        event = {
                    "eventType": "ERROR_EVENT",
                    "timeout": timeout,
                    "title": f'{PROBLEM_TITLE}',
                    "entitySelector": f'entityId({monitor_id})', 
                    "properties": {
                        "dt.event.description": f'The SSL certificate for {hostinfo.hostname} will expire in {expires} days!',
                        "dt.event.source": self.source,
                        "dt.event.allow_davis_merge": False,
                        "Common Name": self.get_common_name(hostinfo.cert),
                        "Issuer": self.get_issuer(hostinfo.cert),
                        "Not Before": notbefore.strftime(datefmt),
                        "Not After": notafter.strftime(datefmt),
                        "Alternative Names": ", ".join(self.get_alt_names(hostinfo.cert)),
                        "Hostname verified": "Yes" if validHostname else "No",
                        "TLS Version": hostinfo.tlsversion[1],
                        "Cipher": f'{hostinfo.cipher[1]} : {hostinfo.cipher[0]}'
                    },
                }
        
        apiurl = "/api/v2/events/ingest"
        headers = {"Content-type": "application/json", "Authorization": f'Api-Token {self.apitoken}'}
        url = self.server + apiurl

        data = json.dumps(event)
        try:
            response = requests.post(url, json=event, headers=headers, verify=False)
            logger.info("{} problem with timeout: {} - Response: {}".format("Closing existing" if clear else "Refreshing/opening new", timeout, response.status_code))
        except:
            logger.error("There was a problem posting error event to Dynatrace: ".format(traceback.format_exc()))

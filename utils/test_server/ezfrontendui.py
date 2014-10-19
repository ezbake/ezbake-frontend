#   Copyright (C) 2013-2014 Computer Sciences Corporation
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

from gevent import monkey; monkey.patch_all()
from gevent.pywsgi import WSGIServer
import web
web.config.debug = False
import gevent
from sys import argv
import yaml
import sys
from modules import ezRPKazoo
from modules import ezRPRegistration

sys.path.append('thrift_modules')
sys.path.append('TSSLSocket')

from ezconfiguration.EzConfiguration import EzConfiguration
from ezconfiguration.helpers import ZookeeperConfiguration, SystemConfiguration
from ezconfiguration.loaders.PropertiesConfigurationLoader import PropertiesConfigurationLoader
from ezconfiguration.loaders.DirectoryConfigurationLoader import DirectoryConfigurationLoader
from ezconfiguration.constants.EzBakePropertyConstants import EzBakePropertyConstants
from ezconfiguration.security.CryptoImplementations import SharedSecretTextCryptoImplementation

import kazoo.client

from ezbake.reverseproxy import EzReverseProxy
from ezbake.reverseproxy.ttypes import *
from ezbake.reverseproxy.constants import SERVICE_NAME as EzFrontendServiceName
from ezbake.frontend.thrift import EzFrontendService
from ezbake.frontend.thrift.ttypes import ServerCertInfo, EzFrontendCertException
from thrift import Thrift
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
import EzInfrastructureTSSLSocket
import ezdiscovery
import urllib
from netifaces import interfaces, ifaddresses, AF_INET
import os
import traceback
import jprops
import glob
import signal
from random import choice
import logging
import time
logger = logging.getLogger('ofe-ui_control')
from socketio import socketio_manage
from socketio.server import SocketIOServer
from socketio.namespace import BaseNamespace
from socketio.mixins import BroadcastMixin
import time
import json


current_milli_time = lambda: int(round(time.time() * 1000))
sslconfig_node = lambda x : os.path.join(ezRPKazoo.KZSSLCONFLOC, x)

zkConfig = None
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
sh = logging.StreamHandler()
sh.setLevel(logging.INFO)
sh.setFormatter(formatter)
logger.addHandler(sh)

def buildUrlPrefix(config, base):
    if len(config['FullUserFacingUrl']) > 0:
        ufup = config['FullUserFacingUrl']
        if '/' not in ufup:
            ufup = ufup + '/'
        return ufup

    if len(config['UserFacingUrlPrefix']) > 0:
        prefix = config['UserFacingUrlPrefix']+'.'
    else:
        prefix = ''
    ufup = prefix+base+'/'+config['UserFacingUrlSuffix']
    return ufup

class state(object):
    def __init__(self):
        self.url=''
        self.reload_configurations()
        self.runningServerConfigurations = {}
        self.mainserver = None
        self.internalhostname = None
        self.socket_resource_path = []
        with (open('ezconfiguration.yaml')) as ssl_config_file:
            ssl_config = yaml.safe_load(ssl_config_file)
            self.configOverrideDir = ssl_config['override_props_dir']
            self.ezconfiguration_dir = ssl_config['ezconfiguration_dir']
            self.keyfile=os.path.join(ssl_config['ssldir'],'application.priv')
            self.certfile=os.path.join(ssl_config['ssldir'],'application.crt')
            self.ca_certs=os.path.join(ssl_config['ssldir'],'ezbakeca.crt')
            self.ezbakesecurityservice_pub=os.path.join(ssl_config['ssldir'],'ezbakesecurityservice.pub')

    def reload_configurations(self):
        with (open('configurations.yaml')) as yamlfile:
            self.serverConfigurations = yaml.safe_load(yamlfile)
            if self.serverConfigurations is not None:
              for k,sc in self.serverConfigurations.iteritems():
                ufup = buildUrlPrefix(sc,self.url)
                sc['link'] = '<a href="https://'+ ufup + '">https://' + ufup + '</a>'
        with (open('test_configurations.yaml')) as yamlfile:
            self.testServerConfigurations = yaml.safe_load(yamlfile)
            for k,sc in self.testServerConfigurations.iteritems():
                url = buildUrlPrefix(sc,self.url)
                sc['link'] = '<a href="https://'+url+'">https://'+url+'</a>'


gState = state()


class WSGILog(object):

    def __init__(self):
        self.log = logger

    def write(self, string):
        self.log.info(string.rstrip("\n"))

def getFirstExposedInterface():
    for ifaceName in interfaces():
        addresses = [i['addr'] for i in ifaddresses(ifaceName).setdefault(AF_INET, [{'addr':'No IP addr'}] )]
        for address in addresses:
            if not address.startswith('127'):
                return address

def htmlprint(dictObj, indent=0):
    p=[]
    p.append('<ul>\n')
    for k,v in dictObj.iteritems():
        if isinstance(v, dict):
            p.append('<li>'+ str(k)+ ':')
            p.append(printitems(v))
            p.append('</li>')
        else:
            p.append('<li>'+ str(k)+ ':&nbsp;'+ str(v)+ '</li>')
    p.append('</ul>\n')
    return '\n'.join(p)


def startServer(configurationNumber):
    if configurationNumber not in gState.runningServerConfigurations:
        current = gState.testServerConfigurations[configurationNumber]

        resource=[]
        if current['isWebSocket']:
            urls = ('/'+current['UpstreamPath']+'/','hello',
                    '/'+current['UpstreamPath']+'/upload','upload',
                    '/'+current['UpstreamPath']+'/wstest','loadWSClientPage',
                    '/'+current['UpstreamPath']+'/socket.io/(.*)','webSocket',
                    '/'+current['UpstreamPath']+'/socket.io.js','sendjs'
                    )
            resource.append(current['UpstreamPath']+'/')
            gState.socket_resource_path.append(current['UpstreamPath'])        
        else:
            urls = ('/'+current['UpstreamPath']+'/','hello',
                    '/'+current['UpstreamPath']+'/upload','upload',)

        resource.append('socket.io')
        socket_io_resource = ''.join(resource)
        app = web.application(urls,globals()).wsgifunc()
        wsgifunc = app
        if gState.cert_reqs != 0:
            logger.info("starting server with configuration %s with ssl" % (str(configurationNumber)))
            runningserver = SocketIOServer((gState.internalhostname,current['UpstreamPort']),wsgifunc,keyfile=gState.keyfile,certfile=gState.certfile,ca_certs=gState.ca_certs,cert_reqs=gevent.ssl.CERT_OPTIONAL,log=WSGILog(),resource=socket_io_resource, policy_server=False)
        else:
            logger.info("starting server with configuration %s WITHOUT ssl" % (str(configurationNumber)))
            runningserver = SocketIOServer((gState.internalhostname,current['UpstreamPort']),wsgifunc,log=WSGILog(),resource=socket_io_resource, policy_server=False)
        gState.runningServerConfigurations[configurationNumber] = runningserver
        runningserver.serve_forever()
        gState.runningServerConfigurations.pop(configurationNumber,None)
        logger.info("starting test server with configuration %s" % (str(configurationNumber)))
    
def stopServer(configurationNumber):
    if configurationNumber in gState.runningServerConfigurations:
        current = gState.testServerConfigurations[configurationNumber]
        if gState.socket_resource_path:
            if current['UpstreamPath'] in gState.socket_resource_path:
                gState.socket_resource_path.remove(current['UpstreamPath'])
        gState.runningServerConfigurations[configurationNumber].stop()

def buildRegistration(configuration):
        if 'UpstreamHost' in configuration:
            uhp = configuration['UpstreamHost']+':'+str(configuration['UpstreamPort'])
        else:
            uhp = gState.internalhostname +':'+str(configuration['UpstreamPort'])

        registration = UpstreamServerRegistration(UserFacingUrlPrefix=buildUrlPrefix(configuration, gState.url),
                                                  AppName=configuration.get('AppName'),
                                                  UpstreamHostAndPort=uhp,
                                                  UpstreamPath=configuration.get('UpstreamPath')+'/',
                                                  timeout=configuration.get('timeout', 10),
                                                  timeoutTries=configuration.get('timeoutTries', 3),
                                                  uploadFileSize=configuration.get('uploadFileSize', 2),
                                                  sticky=configuration.get('sticky', False),
                                                  disableChunkedTransferEncoding=configuration.get('disableChunkedTransferEncoding', False))
        return registration

def registerServer(configuration,host,port):
        try:
            socket = EzInfrastructureTSSLSocket.EzInfrastructureTSSLSocket(host,port, ca_certs=gState.ca_certs, certfile=gState.certfile, keyfile=gState.keyfile)
            transport = TTransport.TBufferedTransport(socket)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = EzReverseProxy.Client(protocol)
            transport.open()
            registration = buildRegistration(configuration)
            client.addUpstreamServerRegistration(registration)
            transport.close()
        except Exception as e:
            logger.error("Exception in registering server: %s" % str(e))

def deregisterServer(deregistration,host,port):
        try:
            socket = EzInfrastructureTSSLSocket.EzInfrastructureTSSLSocket(host,port, ca_certs=gState.ca_certs, certfile=gState.certfile, keyfile=gState.keyfile)
            transport = TTransport.TBufferedTransport(socket)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = EzReverseProxy.Client(protocol)
            transport.open()
            client.removeUpstreamServerRegistration(deregistration)
            transport.close()
        except Exception as e:
            logger.error("Exception in deregistering server: %s" % str(e))

def registerSelf():
        host,port = choice(getOfeServers())
        socket = EzInfrastructureTSSLSocket.EzInfrastructureTSSLSocket(host,int(port), ca_certs=gState.ca_certs, certfile=gState.certfile, keyfile=gState.keyfile)
        transport = TTransport.TBufferedTransport(socket)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = EzReverseProxy.Client(protocol)
        transport.open()
        registration = UpstreamServerRegistration(UserFacingUrlPrefix=gState.url+'/ezfrontend/', AppName='ezfrontend', UpstreamHostAndPort=gState.internalhostname+':'+str(gState.port), UpstreamPath="ezfrontend/", timeout=10, timeoutTries=3, uploadFileSize=256, sticky=True)

        client.addUpstreamServerRegistration(registration)
        transport.close()

def deregisterSelf():
        host,port = choice(getOfeServers())
        logger.info("deregistering with ofe - %s" % host)
        deregisterServer(UpstreamServerRegistration(UserFacingUrlPrefix=gState.url+'/ezfrontend/', AppName='ezfrontend', UpstreamHostAndPort=gState.internalhostname+':'+str(gState.port), UpstreamPath="ezfrontend/", timeout=10, timeoutTries=3, uploadFileSize=256, sticky=True),host,int(port))
               
def deregisterServerFromConfig(config,host,port):
        deregistration = buildRegistration(config)
        deregisterServer(deregistration,host,port)

def removeReverseProxiedPath(path,host,port):
        socket = EzInfrastructureTSSLSocket.EzInfrastructureTSSLSocket(host,port, ca_certs=gState.ca_certs, certfile=gState.certfile, keyfile=gState.keyfile)
        transport = TTransport.TBufferedTransport(socket)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = EzReverseProxy.Client(protocol)
        transport.open()
        client.removeReverseProxiedPath(path)
        transport.close()

def removeReverseProxiedPathFromConfig(config,host,port):
        path = buildUrlPrefix(config,gState.url)
        removeReverseProxiedPath(path,host,port)

def isUpstreamServerRegistered(config,host,port): #UpstreamServerRegistration
        port = int(port)
        socket = EzInfrastructureTSSLSocket.EzInfrastructureTSSLSocket(host,port, ca_certs=gState.ca_certs, certfile=gState.certfile, keyfile=gState.keyfile)
        transport = TTransport.TBufferedTransport(socket)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = EzReverseProxy.Client(protocol)
        transport.open()
        registration = buildRegistration(config)
        rtn = client.isUpstreamServerRegistered(registration)
        transport.close()
        return rtn

def isReverseProxiedPathRegistered(config,host,port): #string
        port = int(port)
        socket = EzInfrastructureTSSLSocket.EzInfrastructureTSSLSocket(host,port, ca_certs=gState.ca_certs, certfile=gState.certfile, keyfile=gState.keyfile)
        transport = TTransport.TBufferedTransport(socket)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = EzReverseProxy.Client(protocol)
        transport.open()
        rtn = client.isReverseProxiedPathRegistered(buildUrlPrefix(config,gState.url))
        transport.close()
        return rtn

def healthStatus(host,port):
        port = int(port)
        socket = EzInfrastructureTSSLSocket.EzInfrastructureTSSLSocket(host,port, ca_certs=gState.ca_certs, certfile=gState.certfile, keyfile=gState.keyfile)
        transport = TTransport.TBufferedTransport(socket)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = EzReverseProxy.Client(protocol)
        transport.open()
        if client.ping():
            return 'healthy'
        else:
            return 'sick'

def pingNoSSL(host,port):
        port = int(port)
        socket = TSocket.TSocket(host,port)
        transport = TTransport.TBufferedTransport(socket)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = EzReverseProxy.Client(protocol)
        transport.open()
        try:
            client.ping()
        except:
            print "ping w/out ssl failed as expected"

def getAllUpstreamServerRegistrations(host,port):
        port = int(port)
        socket = EzInfrastructureTSSLSocket.EzInfrastructureTSSLSocket(host,port, ca_certs=gState.ca_certs, certfile=gState.certfile, keyfile=gState.keyfile)
        transport = TTransport.TBufferedTransport(socket)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = EzReverseProxy.Client(protocol)
        transport.open()
        rtn = client.getAllUpstreamServerRegistrations()
        transport.close()
        return rtn

def getFrontendClient():
    host, port = choice(getOfeServers())
    socket = EzInfrastructureTSSLSocket.EzInfrastructureTSSLSocket(host, int(port), ca_certs=gState.ca_certs, certfile=gState.certfile, keyfile=gState.keyfile)
    client = EzFrontendService.Client(TBinaryProtocol.TBinaryProtocol(TTransport.TBufferedTransport(socket)))
    client._iprot.trans.open()
    return client

def returnFrontendClient(client):
    if isinstance(client, EzFrontendService.Client):
        client._iprot.trans.close()
    del client

def removeCertsForHosts(hosts):
        if not hosts:
            return

        kzUpdated = False
        kz = kazoo.client.KazooClient(zkConfig.getZookeeperConnectionString(), logger=logger)
        kz.start()

        feClient = getFrontendClient()

        for host in hosts:
            if kz.exists(sslconfig_node(host)):
                try:
                    feClient.removeServerCerts(host)
                    logger.info("\nDeleted Cert and Key hostname=%s\n" % (host))
                    kzUpdated = True
                except EzFrontendCertException as e:
                    logger.error("Exception in deleting server cert: %s" % (str(e)))
        if kzUpdated:
            kz.set(ezRPKazoo.KZWATCHLOC, str(current_milli_time()))

        returnFrontendClient(feClient)

class ofestate:
    def GET(self,name):
        userinfo, userinfojson = validateHeaders()
        params = web.input()
        logger.info("user:%s \naccessed: ofestate\nparams: %s\n userJson: '%s'" % (str(userinfo), str(params), str(userinfojson)))
        gState.reload_configurations()
        rtn = []
        host,port = name.split(':',1)
        rtn.append('<!doctype html>')
        rtn.append('<html lang="en">')
        rtn.append('<head>')
        rtn.append('<script src="/ezbstatic/components/platform/platform.js" type="text/javascript"></script>')
        rtn.append('<link rel="import" href="/ezbstatic/components/classification-banner/classification-banner.html">')
        rtn.append('</head>')
        rtn.append('<body>')
        rtn.append('<classification-banner class="banner-component"></classification-banner>')
        rtn.append('<div><br/>'+userinfo+'</div>')
        rtn.append('<div id="UserJson" style="display:none;">' + userinfojson + '</div>')
        rtn.append('<a href="/ezfrontend/control/">main page</a>')
        if (host,port) not in getOfeServers():
            rtn.append('<h3>ofe %s:%s not found</h3>' % (host,port))
        else:
            registrations =  getAllUpstreamServerRegistrations(host,int(port))
            rtn.append('<hr/>')
            for registration in registrations:
                url = registration.UserFacingUrlPrefix
                rtn.append('<ul>')
                rtn.append('<li>link:&nbsp;<a href="https://%s">https://%s</a></li>' % (url,url))
                rtn.append('<li>UpstreamHostAndPort:&nbsp;%s</li>' % (registration.UpstreamHostAndPort))
                rtn.append('<li>AppName:&nbsp;%s</li>' % (registration.AppName))
                rtn.append('<li>timeout:&nbsp;%d</li>' % (registration.timeout))
                rtn.append('<li>timeoutTries:&nbsp;%d</li>' % (registration.timeoutTries))
                rtn.append('<li>uploadFileSize:&nbsp;%d</li>' % (registration.uploadFileSize))
                rtn.append('<li>sticky:&nbsp;%s</li>' % str(registration.sticky))
                rtn.append('<li>disableChunkedTransferEncoding:&nbsp;%s</li>' % str(registration.disableChunkedTransferEncoding))
                rtn.append('<li>UpstreamPath:&nbsp;%s</li>' % (registration.UpstreamPath))
                rtn.append('<li>UserFacingUrlPrefix:&nbsp;%s</li>' % (url))
                rtn.append('</ul>')
                if 'allowoob' in params and params['allowoob']=='1':
                    rtn.append('<form action="/ezfrontend/ofestate/" method="post"><a href="javascript:<a href="javascript:;" onclick="parentNode.submit();">--Ping Without SSL--</a><input type="hidden" name="pingNoSSL"    value="%d|%s|%s"/></form>\n' % (-1,host,port))
                rtn.append('<form action="/ezfrontend/ofestate/" method="post"><a href="javascript:<a href="javascript:;" onclick="parentNode.submit();">--Deregister Instance--</a><input type="hidden" name="deregister"    value="%s|%s|%s|%s|%s|%s"/></form>\n' % (host,port,url,registration.AppName,registration.UpstreamHostAndPort,registration.UpstreamPath))
                rtn.append('<form action="/ezfrontend/ofestate/" method="post"><a href="javascript:<a href="javascript:;" onclick="parentNode.submit();">--Remove Path / All Instances--</a><input type="hidden" name="removeReverseProxiedPath"    value="%s|%s|%s"/></form>\n' % (host,port,url))
                rtn.append('<hr/>')
        rtn.append('</body>')
        return ''.join(rtn)
        

    def POST(self,name):
        userinfo, userinfojson = validateHeaders()
        referer = web.ctx.env.get('HTTP_REFERER')
        gState.reload_configurations()
        data = urllib.unquote(web.data()).decode('utf8')
        logger.info("user:%s \nposted: ofestate\ndata %s" % (str(userinfo), str(data)))
        action,tmp = data.split('=',1)
        #if action == 'pingNoSSL':
        #    serverNumber,host,port = tmp.split('|',2)
        #    port = int(port)
        #    pingNoSSL(host,port)
        #    raise web.seeother(referer)

        if '|' not in tmp:
            logger.error("ERROR - bad post data from user %s to page ofestate. Data logged above" % (userinfo))
            raise web.BadRequest()
        if action == 'deregister':
            logger.info("user: %s Deregistering %s" % (userinfo, data))
            host,port,ufup,an,uhp,up=tmp.split('|',5)
            registration = UpstreamServerRegistration(UserFacingUrlPrefix=ufup, AppName=an, UpstreamHostAndPort=uhp, UpstreamPath=up, timeout=10, timeoutTries=3, uploadFileSize=256, sticky=True)
            deregisterServer(registration,host,int(port))
        elif action == 'removeReverseProxiedPath':
            logger.info("user: %s Deregistering reverse proxied path %s" % (userinfo, data))
            host,port,path=tmp.split('|',2)
            removeReverseProxiedPath(path,host,int(port))
        else:
            logger.info("user:%s \nbad post - reason unknown\nparams: %s" % (userinfo, params))
            raise web.BadRequest()
        raise web.seeother(referer)

class control:
    def get(self,name):
        userinfo, userinfojson = validateHeaders()
        logger.info("user:%s \naccessed: control\n json:%s" % (userinfo, userinfojson))
        rtn = []
        rtn.append('<!doctype html>')
        rtn.append('<html lang="en">')
        rtn.append('<head>')
        rtn.append('<script src="/ezbstatic/components/platform/platform.js" type="text/javascript"></script>')
        rtn.append('<link rel="import" href="/ezbstatic/components/classification-banner/classification-banner.html">')
        rtn.append('</head>')
        rtn.append('<body>')
        rtn.append('<classification-banner class="banner-component"></classification-banner>')
        rtn.append('<div><br/>'+userinfo+'</div>')
        rtn.append('<div id="UserJson" style="display:none;">' + userinfojson + '</div>')
        rtn.append('<style type="text/css">a {text-decoration:none}</style>')
        rtn.append('<div>\n')
        ofe_servers = []
        for host,port in getOfeServers():
            healthy = healthStatus(host,port)
            ofe_servers.append((host,port,healthy))

        rtn.append('<div>\n')
        rtn.append('<h3>Front Ends:</h3>\n')
        for fe in ofe_servers:
            rtn.append('<div>front end server:  <a href="/ezfrontend/ofestate/%s:%s">%s:%s is %s</a></div>' % (fe[0],fe[1],fe[0],fe[1],fe[2]))
        rtn.append('<hr align="left" width="40%"/>\n')

        rtn.append('<h3>Manage Certificates:</h3>\n')
        rtn.append('<div><a href="/ezfrontend/manage/">Manage Certificates</a></div>')
        rtn.append('<hr align="left" width="40%"/>\n')

        rtn.append('<h3>Servers To Register</h3>')
        rtn.append('configured in /opt/ezfrontend_control/configurations.yaml')
        rtn.append('<hr/>\n')
        if gState.serverConfigurations is not None:
          for k,v in gState.serverConfigurations.iteritems():
            rtn.append('<div>\n')
            rtn.append('<h3>Server: %d</h3>\n' % (k))
            rtn.append('<form action="/ezfrontend/control/" method="post">\n')
            if 'UpstreamHost' not in gState.serverConfigurations[k]:
                rtn.append('<h4>Server Status</h4>')
                if k not in gState.runningServerConfigurations:
                    rtn.append('<a href="javascript:;" onclick="parentNode.submit();">--Start--</a> --Stop--\n')
                    rtn.append('<input type="hidden" name="start"  value="%d"/>\n' % (k))
                else:
                    rtn.append('--Start-- <a href="javascript:;" onclick="parentNode.submit();">--Stop--</a>\n')
                    rtn.append('<input type="hidden" name="stop"  value="%d"/>\n' % (k))
            else:
                rtn.append('<h4>External/Real Server - Cannot start/stop</h4>')
            rtn.append('</form>\n')
            rtn.append('<h4>Status With Front Ends</h4>\n')
            for host,port in getOfeServers():
                healthy = healthStatus(host,port)
                instanceRegistered = isUpstreamServerRegistered(v,host,port)
                if not instanceRegistered:
                    pathRegistered = isReverseProxiedPathRegistered(v,host,port)
                else:
                    pathRegistered = True

                rtn.append('<div style="width:70%;">\n')
                rtn.append('<div style="width:50%;float:right;">\n')
                rtn.append('<form action="/ezfrontend/control/" method="post"><a href="javascript:<a href="javascript:;" onclick="parentNode.submit();">--Register--</a><input type="hidden" name="register"  value="%d|%s|%s"/></form>\n' % (k,host,port))
                rtn.append('<form action="/ezfrontend/control/" method="post"><a href="javascript:<a href="javascript:;" onclick="parentNode.submit();">--Deregister--</a><input type="hidden" name="deregister"  value="%d|%s|%s"/></form>\n' % (k,host,port))
                rtn.append('<form action="/ezfrontend/control/" method="post"><a href="javascript:<a href="javascript:;" onclick="parentNode.submit();">--Remove Reverse Proxied Path--</a><input type="hidden" name="removeReverseProxiedPath"  value="%d|%s|%s"/></form>\n' % (k,host,port))
                rtn.append('</div>')
                rtn.append('<div style="width:50%;float:right;">\n')
                rtn.append('OFE: <a href="/ezfrontend/ofestate/%s:%s">%s:%s is %s</a>' % (host,port,host,port,healthy))
                #rtn.append('<div style="clear:right;"></div>')
                rtn.append('<div style="width:80%;align:center;">')
                rtn.append('<div style="width:50%;float:right;">Instance Registered</div>')
                rtn.append('<div style="width:50%;float:right">Path Registered</div>')
                rtn.append('<div style="clear:right;"></div>')
                rtn.append('<div style="width:50%%;float:right;">%s</div>' % (str(instanceRegistered)))
                rtn.append('<div style="width:50%%;float:right">%s</div>' % (str(pathRegistered)))
                rtn.append('</div>')
                rtn.append('</div>')
                rtn.append('</div>\n')
                rtn.append('<div style="clear:both;"></div>\n')
            rtn.append('Reverse Proxy Configuration Details')
            rtn.append(htmlprint(v))
            rtn.append('</div>\n')
            rtn.append('<hr align="left" width="40%"/>')
        rtn.append('</div>\n')
        rtn.append('<h3>Test Servers To Register</h3>')
        rtn.append('configured in /opt/ezfrontend_control/test_configurations.yaml')
        rtn.append('<hr/>') # full width
        for k,v in gState.testServerConfigurations.iteritems():
            rtn.append('<div>\n')
            rtn.append('<h3>Server: %d</h3>\n' % (k))
            rtn.append('<form action="/ezfrontend/control/" method="post">\n')
            if 'UpstreamHost' not in gState.testServerConfigurations[k]:
                rtn.append('<h4>Test Server Status</h4>')
                if k not in gState.runningServerConfigurations:
                    rtn.append('<a href="javascript:;" onclick="parentNode.submit();">--Start--</a> --Stop--\n')
                    rtn.append('<input type="hidden" name="start"  value="%d"/>\n' % (k))
                else:
                    rtn.append('--Start-- <a href="javascript:;" onclick="parentNode.submit();">--Stop--</a>\n')
                    rtn.append('<input type="hidden" name="stop"  value="%d"/>\n' % (k))
            else:
                rtn.append('<h4>External/Real Server - Cannot start/stop</h4>')
            rtn.append('</form>\n')
            rtn.append('<h4>Status With Front Ends</h4>\n')
            for host,port in getOfeServers():
                healthy = healthStatus(host,port)
                instanceRegistered = isUpstreamServerRegistered(v,host,port)
                if not instanceRegistered:
                    pathRegistered = isReverseProxiedPathRegistered(v,host,port)
                else:
                    pathRegistered = True

                rtn.append('<div style="width:70%;">\n')
                rtn.append('<div style="width:50%;float:right;">\n')
                rtn.append('<form action="/ezfrontend/control/" method="post"><a href="javascript:<a href="javascript:;" onclick="parentNode.submit();">--Register--</a><input type="hidden" name="registert"  value="%d|%s|%s"/></form>\n' % (k,host,port))
                rtn.append('<form action="/ezfrontend/control/" method="post"><a href="javascript:<a href="javascript:;" onclick="parentNode.submit();">--Deregister--</a><input type="hidden" name="deregistert"  value="%d|%s|%s"/></form>\n' % (k,host,port))
                rtn.append('<form action="/ezfrontend/control/" method="post"><a href="javascript:<a href="javascript:;" onclick="parentNode.submit();">--Remove Reverse Proxied Path--</a><input type="hidden" name="removeReverseProxiedPatht"  value="%d|%s|%s"/></form>\n' % (k,host,port))
                rtn.append('</div>')
                rtn.append('<div style="width:50%;float:right;">\n')
                rtn.append('OFE: <a href="/ezfrontend/ofestate/%s:%s">%s:%s is %s</a>' % (host,port,host,port,healthy))
                #rtn.append('<div style="clear:right;"></div>')
                rtn.append('<div style="width:80%;align:center;">')
                rtn.append('<div style="width:50%;float:right;">Instance Registered</div>')
                rtn.append('<div style="width:50%;float:right">Path Registered</div>')
                rtn.append('<div style="clear:right;"></div>')
                rtn.append('<div style="width:50%%;float:right;">%s</div>' % (str(instanceRegistered)))
                rtn.append('<div style="width:50%%;float:right">%s</div>' % (str(pathRegistered)))
                rtn.append('</div>')
                rtn.append('</div>')
                rtn.append('</div>\n')
                rtn.append('<div style="clear:both;"></div>\n')
            rtn.append('Reverse Proxy Configuration Details')
            rtn.append(htmlprint(v))
            rtn.append('</div>\n')
            rtn.append('<hr align="left" width="40%"/>')
        rtn.append('</div>\n')
        rtn.append('</body>')
        return ''.join(rtn)

    def GET(self,name):
        gState.reload_configurations()
        return self.get(name)

    def POST(self,name):
        redirect = 'https://'+ str(web.ctx.env.get('HTTP_X_ORIGINAL_HOST'))+'/ezfrontend/control/'
        userinfo, userinfojson = validateHeaders()
        gState.reload_configurations()
        data = urllib.unquote(web.data()).decode('utf8')
        logger.info("user:%s \nposted: control\ndata: %s" % (userinfo, data))
        action,tmp = data.split('=',1)
        if '|' in tmp:
            serverNumber,host,port = tmp.split('|',2)
            port = int(port)
        else:
            serverNumber = tmp
        serverNumber = int(serverNumber)
        
        if action == 'start':
            logger.info("user:%s \nstarting test server: %d\n" % (userinfo, serverNumber))
            gevent.spawn(startServer,serverNumber)
        elif action == 'stop':
            logger.info("user:%s \nstopping test server %d\n" % (userinfo, serverNumber))
            stopServer(serverNumber)
        elif action == 'register':
            logger.info("user:%s \nregistering: %s\n" % (userinfo, str(gState.serverConfigurations[serverNumber])))
            registerServer(gState.serverConfigurations[serverNumber],host,port)
        elif action == 'registert':
            logger.info("user:%s \nregistering: %s\n" % (userinfo, str(gState.testServerConfigurations[serverNumber])))
            registerServer(gState.testServerConfigurations[serverNumber],host,port)
        elif action == 'deregister':
            logger.info("user: %s\nderegistering: %s\n" % (userinfo, str(gState.serverConfigurations[serverNumber])))
            deregisterServerFromConfig(gState.serverConfigurations[serverNumber],host,port)
        elif action == 'deregistert':
            logger.info("user: %s\nderegistering: %s" % (userinfo, str(gState.testServerConfigurations[serverNumber])))
            deregisterServerFromConfig(gState.testServerConfigurations[serverNumber],host,port)
        elif action == 'removeReverseProxiedPath':
            logger.info("user: %s\nremoving reverse proxied path: %s\n" % (userinfo, str(gState.serverConfigurations[serverNumber])))
            removeReverseProxiedPathFromConfig(gState.serverConfigurations[serverNumber],host,port)
        elif action == 'removeReverseProxiedPatht':
            logger.info("user: %s\nremoving reverse proxied path: %s\n" % (userinfo, str(gState.testServerConfigurations[serverNumber])))
            removeReverseProxiedPathFromConfig(gState.testServerConfigurations[serverNumber],host,port)
        logger.error("user: %s\ninvalid post to control\n" % (str(userinfo)))
        raise web.seeother(redirect)

'''
Class to manage certificates
'''
class manage:
    def GET(self):
        userinfo, userinfojson = validateHeaders()
        logger.info("user:%s \naccessed: manage\n json:%s" % (userinfo, userinfojson))

        rtn_upl = []
        rtn_del = []
        upload_servers = {}
        delete_servers = {}
        path = web.ctx.env['PATH_INFO'].strip('/')
        rtn_upl.append('<!doctype html>')
        rtn_upl.append('<html lang="en">')
        rtn_upl.append('<head>')
        rtn_upl.append('<script src="/ezbstatic/components/platform/platform.js" type="text/javascript"></script>')
        rtn_upl.append('<link rel="import" href="/ezbstatic/components/classification-banner/classification-banner.html">')
        rtn_upl.append('</head>')
        rtn_upl.append('<body>')
        rtn_upl.append('<classification-banner class="banner-component"></classification-banner>')
        rtn_upl.append('<div><br/>'+userinfo+'</div>')
        rtn_upl.append('<div id="UserJson" style="display:none;">' + userinfojson + '</div>')
        rtn_upl.append('<style type="text/css">a {text-decoration:none}</style>')
        rtn_upl.append('<a href="/ezfrontend/control/">Return to main page</a>')
        rtn_upl.append('<h3>Manage Certificates:</h3>\n')

        ofe_host, port = choice(getOfeServers())
        registrations =  getAllUpstreamServerRegistrations(ofe_host,int(port))

        kz = kazoo.client.KazooClient(zkConfig.getZookeeperConnectionString(), logger=logger)
        kz.start()

        for registration in registrations:
            #map registrations to host_name
            serverName = ezRPRegistration.get_ngx_server_name(registration).strip()
            host_name, host_port = ezRPRegistration.getUpstreamHostAndPort(registration)

            if serverName:
                #if we have a specified user facing server name, use that instead
                host_name = serverName

            if kz.exists(sslconfig_node(host_name)):
                if host_name not in delete_servers:
                     delete_servers[host_name] = [registration]
                else:
                     delete_servers[host_name].append(registration)
            else:
                if host_name not in upload_servers:
                    upload_servers[host_name] = [registration]
                else:
                    upload_servers[host_name].append(registration)
             
        if upload_servers:
            rtn_upl.append('<b>Upload Certificates and Keys</b>')
            rtn_upl.append('<form action="/' + path + '/uploadCert" method="post" enctype="multipart/form-data">')
            for server, registrations in upload_servers.iteritems():
                rtn_upl.append('<ul>Server: %s' % (server))
                for registration in registrations:
                    location = ezRPRegistration.get_ngx_location(registration).strip()
                    upstream_host, upstream_port = ezRPRegistration.getUpstreamHostAndPort(registration)
                    rtn_upl.append('<li>%s&nbsp;=>&nbsp;%s:%d</li>' % (location, upstream_host, upstream_port))
                rtn_upl.append('</ul>')
                rtn_upl.append('Certificate  <input type="file" name="upload_cert:%s">'%(server))
                rtn_upl.append('Key <input type="file" name="upload_key:%s">'%(server))
                rtn_upl.append('<br><hr>')
            rtn_upl.append('<input type="submit" value="Upload">')
            rtn_upl.append('</form>')
            
        if delete_servers:
            rtn_del.append('<b>Delete Certificates and Keys</b>')
            rtn_del.append('<form action="/' + path + '/deleteCert" method="post" enctype="multipart/form-data">')
            for server, registrations in delete_servers.iteritems():
                rtn_del.append('<ul>Server: %s' % (server))
                for registration in registrations:
                    location = ezRPRegistration.get_ngx_location(registration).strip()
                    upstream_host, upstream_port = ezRPRegistration.getUpstreamHostAndPort(registration)
                    rtn_del.append('<li>%s&nbsp;=>&nbsp;%s:%d</li>' % (location, upstream_host, upstream_port))
                rtn_del.append('</ul>')
                rtn_del.append('Select to delete Certificate and Key <input type="checkbox" name="delete_:%s">'%(server))
                rtn_del.append('<br><hr>')
            rtn_del.append('<input type="submit" value="Delete">')
            rtn_del.append('</form>')
        
        return ''.join(rtn_upl + ["<hr> <br>"] + rtn_del + ['</body>'])

    def POST(self):
        return
        
class uploadCerts:
    '''
    Upload cert and key of host(s)
    '''
    def POST(self):
        form = web.input()
        rtn = []
        rtn.append('<!doctype html>')
        rtn.append('<html lang="en">')
        rtn.append('<head>')
        rtn.append('<script src="/ezbstatic/components/platform/platform.js" type="text/javascript"></script>')
        rtn.append('<link rel="import" href="/ezbstatic/components/classification-banner/classification-banner.html">')
        rtn.append('</head>')
        rtn.append('<body>')
        rtn.append('<classification-banner class="banner-component"></classification-banner>')
        rtn.append("<h1>Uploaded Certificate and Key </h1>")
        headers = []
        serverCerts = {}

        for k, v in form.iteritems():
            if not (k.startswith('upload_') and len(str(v)) > 0):
                continue

            cert_type, host_name = k.split(':')[0], k.split(':')[1]

            if host_name not in serverCerts:
                serverCerts[host_name] = {'crt':None, 'key':None}

            if 'cert' in cert_type:
                serverCerts[host_name]['crt'] = str(v)
            else:
                serverCerts[host_name]['key'] = str(v)

        if serverCerts:
            kz = kazoo.client.KazooClient(zkConfig.getZookeeperConnectionString(), logger=logger)
            kz.start()
            feClient = getFrontendClient()

            #save certs to database and update zookeeper
            for server, certData in serverCerts.iteritems():
                try:
                    feClient.addServerCerts(server, ServerCertInfo(certificateContents=certData['crt'], keyContents=certData['key']))
                    logger.info("Uploaded Cert and Key for %s" % server)
                    rtn.append("Uploaded Certificate and key for host: %s <br>" % server)
                except EzFrontendCertException as e:
                    logger.error("Error in Uploading Cert and Key for %s: %s" % (server, str(e)))
                    rtn.append("Error in uploading Certificate and Key for host: %s <br>" % server)

            #trigger zoo keeper watch
            kz.set(ezRPKazoo.KZWATCHLOC, str(current_milli_time()))
            #return fe client
            returnFrontendClient(feClient)
            
        rtn.append('<br>')
        rtn.append('<hr>')
        rtn.append('<a href="/ezfrontend/manage/">Return to Manage Certificates page</a>')
        rtn.append('</body>')
        return ''.join(rtn)

class deleteCerts:
    '''
    delete cert and key of host(s)
    '''
    def POST(self):
        form = web.input()
        rtn = []
        rtn.append('<!doctype html>')
        rtn.append('<html lang="en">')
        rtn.append('<head>')
        rtn.append('<script src="/ezbstatic/components/platform/platform.js" type="text/javascript"></script>')
        rtn.append('<link rel="import" href="/ezbstatic/components/classification-banner/classification-banner.html">')
        rtn.append('</head>')
        rtn.append('<body>')
        rtn.append('<classification-banner class="banner-component"></classification-banner>')
        rtn.append("<h1>Deleted Certificate and Key </h1>")
        headers = []
        updatedZKNodes = []
        hostsToDelete = set()
        kz = None

        for k, v in form.iteritems():
            if not k.startswith('delete_'):
                continue
            hostsToDelete.add(k.split(':')[1])

        if hostsToDelete:
            removeCertsForHosts(hostsToDelete)
            for h in hostsToDelete:
                rtn.append("Deleted Certificate and key for host: %s <br>" %(h))

        rtn.append('<br>')
        rtn.append('<hr>')
        rtn.append('<a href="/ezfrontend/manage/">Return to Manage Certificates page</a>')
        rtn.append('</body>')
        return ''.join(rtn)

class hello:
    def GET(self):
        userinfo, userinfojson = validateHeaders()
        logger.info("user:%s \naccessed: diagnostic web page %s\n" % (userinfo, web.ctx.homepath+web.ctx.fullpath))
        headers = []
        for key in web.ctx.env:
            headers.append('<li>'+str(key)+': '+str(web.ctx.env[key])+'</li>')
        
        qp = web.input()
        queryParameters = []
        for key in qp:
          queryParameters.append(key+":\t"+qp[key])
        rtn = []
        rtn.append('<html>')
        rtn.append('<!doctype html>')
        rtn.append('<html lang="en">')
        rtn.append('<head>')
        rtn.append('<script src="/ezbstatic/components/platform/platform.js" type="text/javascript"></script>')
        rtn.append('<link rel="import" href="/ezbstatic/components/classification-banner/classification-banner.html">')
        rtn.append('</head>')
        rtn.append('<body>')
        rtn.append('<classification-banner class="banner-component"></classification-banner>')
        rtn.append('<br/><h3>port</h3>'+''+'<h3>headers</h3><ul>'+"\n".join(headers)+'</ul><h3>query parameters</h3><ul>'+"\n".join(queryParameters)+'</ul>')
        
        path = web.ctx.env['PATH_INFO'].strip('/')
        
        # Upload form
        rtn.append('<h3>Upload</h3>')
        rtn.append('<form action="/' + path + '/upload" method="post" enctype="multipart/form-data">')
        rtn.append('<input type="file" name="upload_file">')
        rtn.append('<input type="submit" value="Upload">')
        rtn.append('</form>')
        
        if path in gState.socket_resource_path:
            rtn.append('<h3>WebSocket</h3>')
            web_socket_url = 'https://'+ str(web.ctx.env.get('HTTP_X_ORIGINAL_HOST'))+'/'+ path + '/wstest'
            rtn.append('<a href = "' + web_socket_url + '">WebSocket Test </a>')
        
        rtn.append('</body></html>')
        return ''.join(rtn)
        
render = web.template.render('./')
        
class loadWSClientPage:
    ''' 
    Load WebSocket Test page
    ''' 
    def GET(self):
        path = web.ctx.env['PATH_INFO'].strip('/').split('/')[0]
        
        if path in gState.socket_resource_path:
            return render.websocket_test_page(web.ctx.env.get('HTTP_X_ORIGINAL_HOST', 'localhost'), path)
        # This should not happen
        logger.error('Web Socket Test Page called without enabling SocketIOServer')
        raise web.internalerror('Web Socket Test Page called without enabling SocketIOServer')
        
class sendjs:
    ''' 
    Send node.io.js file for the client
    ''' 
    def GET(self):
         try:
            js = open('./socket.io.js')    
            return js.read()
         except:
            logger.info('socket.io.js Not Found')
            return "<h1>Not Found</h1>"
        
class webSocket:
    ''' 
    Service Websocket request
    ''' 
    def GET(self, name):
        # Extract the resource path
        path = web.ctx.env['PATH_INFO'].strip('/').split('/')[0]
       
        if path in gState.socket_resource_path:
             # It must be socket.io request, strip the resource path
             path = web.ctx.env['PATH_INFO'].strip('/'+path+'/')
        if path.startswith("socket.io"):
            socketio_manage(web.ctx.env , {
                                          '/test': dateNamespace,
                                          }, request = name)
        else:
           logger.info('socket.io not in PATH_INFO')
           return "<h1>Not Found</h1>"
           
           
class dateNamespace(BaseNamespace, BroadcastMixin):
    '''    
     Updates epoch time, ip address and
     DN constantly. Echos back received message.
    '''
    def recv_connect(self):
        dn = str(self.environ['HTTP_X_CLIENT_CERT_S_DN'])
        ip = str(self.environ.get('REMOTE_ADDR', 'UNKNOWN'))
        def sendTime():
            while True:
                dtime = time.time()
                self.emit('time_data', {
                                        'time':int(dtime),
                                        'ipaddr':ip,
                                        'DN':dn
                                        })
                gevent.sleep(0.1)
        self.spawn(sendTime)
    
    def on_msg(self, message):
        '''
         Echo back the received message
        '''
        self.emit('msg',{'message':message})  
                                       
class upload:
    '''
    Upload file into /tmp dir
    '''
    def POST(self):
        length = web.ctx.env['CONTENT_LENGTH']
        # Note: upload_file is the 'name' in form
        form = web.input(upload_file={})
        dir = '/tmp'
        if 'upload_file' in form:
             filepath = form.upload_file.filename.replace('\\','/') 
             filename = filepath.split('/')[-1] 
             fout = open(dir +'/'+ filename,'w')
             fout.write(form.upload_file.file.read()) 
             fout.close() 
             logger.info('uploaded ' + length + ' bytes into file:' + dir +'/'+ filename)
             htmlText = '<!doctype html><html lang="en"><head>'
             htmlText += '<script src="/ezbstatic/components/platform/platform.js" type="text/javascript"></script>'
             htmlText += '<link rel="import" href="/ezbstatic/components/classification-banner/classification-banner.html">'
             htmlText += '</head><body><classification-banner class="banner-component"></classification-banner>'
             htmlText += "<h1>Upload</h1>Uploaded file: \"" + filename + "\" of length: " + length + " bytes into " + dir
             return htmlText

        return ("<h1> Could not read file </h1>")

def verify_sign(public_key_loc, signature, data):
    '''    
    Verifies with a public key from whom the data came that it was indeed 
    signed by their private key
    param: public_key_loc Path to public key
    param: signature String signature to be verified
    return: Boolean. True if the signature is valid; False otherwise. 
    '''
    from Crypto.PublicKey import RSA 
    from Crypto.Signature import PKCS1_v1_5 
    from Crypto.Hash import SHA256 
    from base64 import b64decode 
    from base64 import b64encode
    pub_key = open(public_key_loc, "r").read() 
    rsakey = RSA.importKey(pub_key) 
    signer = PKCS1_v1_5.new(rsakey) 
    digest = SHA256.new() 
    # Assumes the data is base64 encoded to begin with
    #digest.update(b64decode(data)) 
    #digest.update(b64encode(data))
    digest.update(data)
    if signer.verify(digest, b64decode(signature)):
        logger.info("SIGNATURE VERIFIED FOR: %s" % str(digest))
        return True
    logger.error("Signature not verified for:%s " % data)
    return False
           
def getCn(subject):
    csvs = subject.split(',')
    for csv in csvs:
        kv = csv.strip().rstrip()
        key,value = kv.split('=',1)
        if key == 'CN':
            return value
    logger.error("no CN in subject: %s" % subject)
    raise web.unauthorized


def validateCn(cn):
    if cn.startswith('_Ez_'):
        logger.info("access granted to special cert with prefix _Ez_: %s" % cn)
        return True
    with (open('authorized_users.yaml')) as userfile:
        authorized_users = yaml.safe_load(userfile)
        if authorized_users is not None:
            for authorized_user in authorized_users:
                if cn == authorized_user:
                    logger.info("validated access for user (%s) using authorization file" % cn)
                    return True
    return False


def validateProxyToken(proxyTokenJson):
    '''
    Checks the expiration of the proxy token.
    Returns a tuple - (User DN, TokenExpirationStatus)
    TokenExpirationStatus: True - token valid. Proxy Token has not expired
                           False - token invalid.
    '''
    try:
        proxyToken = json.loads(proxyTokenJson)
        tokenExpiration = int(proxyToken.get('notAfter'))
        userDN = proxyToken.get('x509').get('subject')

        if tokenExpiration > current_milli_time():
            return userDN, True
        else:
            logger.error("ezb proxy token token has expired: %i" % tokenExpiration)
    except Exception as ex:
        logger.error('Exception in validating proxy token for user {%s}: %s' % (getCn(userDN), str(ex)))
    return userDN, False


def validateUser(cn, userJsonInfo):
    ezAdminProject = '_Ez_internal_project_'
    ezAdminGroup = '_Ez_administrator'
    userCreds = json.loads(userJsonInfo)

    for groups in [p.get('groups') for p in userCreds.get('projects') if ('projectName' in p and p.get('projectName') == ezAdminProject)]:
        if ezAdminGroup in groups:
            logger.info("validated access for user (%s) using json header" % cn)
            return True
    return False 


def validateHeaders():
    headers = {}
    for key in web.ctx.env:
        headers[str(key)] =  str(web.ctx.env[key])

    if 'HTTP_EZB_VERIFIED_USER_INFO' not in headers or 'HTTP_EZB_VERIFIED_SIGNATURE' not in headers or \
       'HTTP_EZB_USER_INFO_JSON' not in headers or 'HTTP_EZB_USER_INFO_JSON_SIGNATURE' not in headers:
        logger.error("unauthorized access attemp, headers not properly set by ezfrontend")
        raise web.unauthorized()

    valid = (verify_sign(gState.ezbakesecurityservice_pub, headers['HTTP_EZB_VERIFIED_SIGNATURE'], headers['HTTP_EZB_VERIFIED_USER_INFO']) and \
             verify_sign(gState.ezbakesecurityservice_pub, headers['HTTP_EZB_USER_INFO_JSON_SIGNATURE'], headers['HTTP_EZB_USER_INFO_JSON']))

    if not valid:
        logger.error("unauthorized access (signature mismatch) attempt by: %s" % (headers['HTTP_EZB_VERIFIED_USER_INFO']))
        raise web.unauthorized()

    userDN, proxyTokenValid = validateProxyToken(headers['HTTP_EZB_VERIFIED_USER_INFO'])
    if not proxyTokenValid:
        raise web.unauthorized

    cn = getCn(userDN)

    if not (validateUser(cn, headers['HTTP_EZB_USER_INFO_JSON']) or validateCn(cn)):
        logger.error("unauthorized access attempt by user with CN: %s\nUserInfo: %s" % (cn, headers['HTTP_EZB_USER_INFO_JSON']))
        raise web.unauthorized

    return userDN, headers['HTTP_EZB_USER_INFO_JSON']

           
def getOfeServers():
    rtn = []
    endpoints = ezdiscovery.get_endpoints('EzBakeFrontend', EzFrontendServiceName)
    for endpoint in endpoints:
        name,port = endpoint.split(':',1)
        rtn.append((name,port))
    return rtn

           
def getEzProperties():
    #load default configurations
    config = EzConfiguration()
    logger.info("loaded default ezconfiguration properties")

    #load configuration overrides
    overrideLoader = DirectoryConfigurationLoader(gState.configOverrideDir)
    config = EzConfiguration(PropertiesConfigurationLoader(config.getProperties()), overrideLoader)
    logger.info("loaded property overrides")

    #load cryptoImpl
    cryptoImpl = SystemConfiguration(config.getProperties()).getTextCryptoImplementer()
    if not isinstance(cryptoImpl, SharedSecretTextCryptoImplementation):
        logger.warn("Couldn't get a SharedSecretTextCryptoImplementation. Is the EZB shared secret set properly?")

    return config.getProperties(cryptoImpl)


def handler(signalnum,frame):
    gState.mainserver.stop()
           
def main():
    import logging.handlers
    wfh = logging.handlers.WatchedFileHandler('/opt/ezfrontend-ui/ezfrontend-ui.log')
    wfh.setLevel(logging.INFO)
    wfh.setFormatter(formatter)
    logger.addHandler(wfh)
    # comment the next line to also send the log to the terminal
    logger.removeHandler(sh)
           
    if "TESTNOSSL" in os.environ:
        gState.cert_reqs=0
    else:  
        gState.cert_reqs=1
           
    signal.signal(signal.SIGTERM, handler)

    ezProps = getEzProperties()

    global zkConfig
    zkConfig = ZookeeperConfiguration(ezProps)
    gState.port = int(ezProps.get('ofe.tester.port', -1))
    gState.url = ezProps.get('web.application.external.domain')
    gState.internalhostname = ezProps.get('internal_hostname')
    ezdiscovery.connect(zkConfig.getZookeeperConnectionString())

    #kz = kazoo.client.KazooClient(zkConfig.getZookeeperConnectionString(), logger=logger, handler=kazoo.handlers.gevent.SequentialGeventHandler())
    kz = kazoo.client.KazooClient(zkConfig.getZookeeperConnectionString(), logger=logger)
    kz.start()
    kz.ensure_path(ezRPKazoo.KZWATCHLOC)
    kz.ensure_path(ezRPKazoo.KZSSLCONFLOC)
    kz = None

    urls = ('/ezfrontend/control/(.*)','control',
            '/ezfrontend/ofestate/(.*)','ofestate',
            '/ezfrontend/manage/','manage',
            '/ezfrontend/manage/uploadCert','uploadCerts',
            '/ezfrontend/manage/deleteCert','deleteCerts'
             )
    app = web.application(urls,globals()).wsgifunc()
    wsgifunc = app
    try:
        registerSelf()
    except Exception as e:
        logger.exception('Error in registering with Ofe: %s' % str(e))
        return
    try:
        gState.mainserver = WSGIServer((gState.internalhostname, gState.port), wsgifunc,
                                       keyfile=gState.keyfile, certfile=gState.certfile, ca_certs=gState.ca_certs, cert_reqs=gevent.ssl.CERT_OPTIONAL,
                                       log=WSGILog())
        gState.mainserver.serve_forever()
    except Exception as e:
        logger.error('Exception raised while running server: %s\n%s' % (str(e), traceback.format_exc()))
    try:
        deregisterSelf()
    except Exception as e:
        logger.error('Error in deregistering with Ofe: %s' % str(e))
    logger.info('done. exiting.')
           
if __name__ == '__main__':
   main()


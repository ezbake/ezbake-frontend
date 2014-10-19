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
import gevent
from sys import argv
import yaml
import sys
sys.path.append('thrift_modules')
sys.path.append('TSSLSocket')

from ezbake.reverseproxy import EzReverseProxy
from ezbake.reverseproxy.ttypes import *
from ezbake.reverseproxy.constants import SERVICE_NAME as EzFrontendServiceName
from thrift import Thrift
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
import EzInfrastructureTSSLSocket
import ezdiscovery
import urllib
from netifaces import interfaces, ifaddresses, AF_INET
import time


def buildRegistration(configurationNumber):
        current = gState.serverConfigurations[configurationNumber]
        ufup = current['UserFacingUrlPrefix']
        an = current['AppName']
        if 'UpstreamHost' in current:
            uhp = current['UpstreamHost']+':'+str(current['UpstreamPort'])
        else:
            uhp = getFirstExposedInterface() +':'+str(current['UpstreamPort'])
        up =  current['UpstreamPath']
        registration = UpstreamServerRegistration(UserFacingUrlPrefix=ufup, AppName=an, UpstreamHostAndPort=uhp, UpstreamPath=up, timeout=10, timeoutTries=3)
        return registration

def registerServer(configurationNumber,host,port):
        socket = EzInfrastructureTSSLSocket.EzInfrastructureTSSLSocket(host,port, ca_certs='ssl_ezdeploy/ezbakeca.crt', certfile='ssl_ezdeploy/application.crt', keyfile='ssl_ezdeploy/application.priv')
        transport = TTransport.TBufferedTransport(socket)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = EzReverseProxy.Client(protocol)
        transport.open()
        registration = buildRegistration(configurationNumber)
        print registration
        client.addUpstreamServerRegistration(registration)
        transport.close()
               
def deregisterServer(configurationNumber,host,port):
        socket = EzInfrastructureTSSLSocket.EzInfrastructureTSSLSocket(host,port, ca_certs='ssl_ezdeploy/ezbakeca.crt', certfile='ssl_ezdeploy/application.crt', keyfile='ssl_ezdeploy/application.priv')
        transport = TTransport.TBufferedTransport(socket)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = EzReverseProxy.Client(protocol)
        transport.open()
        deregistration = buildRegistration(configurationNumber)
        client.removeUpstreamServerRegistration(deregistration)
        transport.close()

def removeReverseProxiedPath(configurationNumber,host,port):
        socket = EzInfrastructureTSSLSocket.EzInfrastructureTSSLSocket(host,port, ca_certs='ssl_ezdeploy/ezbakeca.crt', certfile='ssl_ezdeploy/application.crt', keyfile='ssl_ezdeploy/application.priv')
        transport = TTransport.TBufferedTransport(socket)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = EzReverseProxy.Client(protocol)
        transport.open()
        client.removeReverseProxiedPath(gState.serverConfigurations[configurationNumber]['UserFacingUrlPrefix'])
        transport.close()

def isUpstreamServerRegistered(configurationNumber,host,port): #UpstreamServerRegistration
        port = int(port)
        socket = EzInfrastructureTSSLSocket.EzInfrastructureTSSLSocket(host,port, ca_certs='ssl_ezdeploy/ezbakeca.crt', certfile='ssl_ezdeploy/application.crt', keyfile='ssl_ezdeploy/application.priv')
        transport = TTransport.TBufferedTransport(socket)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = EzReverseProxy.Client(protocol)
        transport.open()
        registration = buildRegistration(configurationNumber)
        print registration
        rtn = client.isUpstreamServerRegistered(registration)
        transport.close()
        return rtn

def isReverseProxiedPathRegistered(configurationNumber,host,port): #string
        port = int(port)
        socket = EzInfrastructureTSSLSocket.EzInfrastructureTSSLSocket(host,port, ca_certs='ssl_ezdeploy/ezbakeca.crt', certfile='ssl_ezdeploy/application.crt', keyfile='ssl_ezdeploy/application.priv')
        transport = TTransport.TBufferedTransport(socket)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = EzReverseProxy.Client(protocol)
        transport.open()
        rtn = client.isReverseProxiedPathRegistered(gState.serverConfigurations[configurationNumber]['UserFacingUrlPrefix'])
        transport.close()
        return rtn

def healthStatus(host,port):
        port = int(port)
        socket = EzInfrastructureTSSLSocket.EzInfrastructureTSSLSocket(host,port, ca_certs='ssl_ezdeploy/ezbakeca.crt', certfile='ssl_ezdeploy/application.crt', keyfile='ssl_ezdeploy/application.priv')
        transport = TTransport.TBufferedTransport(socket)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = EzReverseProxy.Client(protocol)
        transport.open()
        if client.ping():
            print 'healthy sleeping 5 seconds'
            time.sleep(5)
            return 'healthy'
        else:
            print 'sick'
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
        socket = EzInfrastructureTSSLSocket.EzInfrastructureTSSLSocket(host,port, ca_certs='ssl_ezdeploy/ezbakeca.crt', certfile='ssl_ezdeploy/application.crt', keyfile='ssl_ezdeploy/application.priv')
        transport = TTransport.TBufferedTransport(socket)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = EzReverseProxy.Client(protocol)
        transport.open()
        rtn = client.getAllUpstreamServerRegistrations()
        transport.close()
        return rtn


def getOfeServers():
    rtn = []
    endpoints = ezdiscovery.get_endpoints('system_services', EzFrontendServiceName)
    print "found endpoints:"
    print endpoints
    for endpoint in endpoints:
        name,port = endpoint.split(':',1)
        rtn.append((name,port))
    return rtn

        
def main(port=1025,zkstring='127.0.0.1:2181'):
    ezdiscovery.connect(zkstring)
    ofeServers = getOfeServers()
    for ofe in ofeServers:
        print 'pinging ofe: '+str(ofe)
        healthStatus(ofe[0],int(ofe[1]))
        

if __name__ == '__main__':
    if len(sys.argv) > 1:
        main(zkstring=sys.argv[1])
    else:
        main()

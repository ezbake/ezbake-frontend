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

import os
import stat
import socket
import signal
import subprocess
import shutil
import yaml
import hashlib
import OpenSSL
import ezRPKazoo
import ezRPNginx
import ezRPRegistration
import ezRPConfig as gConfig

from random import choice
from operator import attrgetter

from kazoo.exceptions import NoNodeError

from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol

from ezbake.reverseproxy import EzReverseProxy
from ezbake.reverseproxy.ttypes import *


"""
Module to create Nginx configuration file
"""

class Configurer(object):
    class Sanity(object):
        def __init__(self,UpstreamNumber,UpstreamPath):
            self.UpstreamNumber = UpstreamNumber
            self.UpstreamPath = UpstreamPath

    class Location(object):
        def __init__(self, location, proxy_pass, server_name, upstream_path, upstream_host, upstream_port, upstream_timeout, upstream_timeout_tries, upstream_upload_file_size, sticky, disable_chunked_encoding):
            if not location.startswith('/'):
                location = '/'+location
            if not location.endswith('/'):
                location = location + '/'
            while location.startswith('//'):
                location = location[1:]
            while location.endswith('//'):
                location = location[0:-1]
            self.location = location

            if not upstream_path.startswith('/'):
                upstream_path = '/' + upstream_path
            if not upstream_path.endswith('/'):
                upstream_path = upstream_path + '/'
            while upstream_path.startswith('//'):
                upstream_path = upstream_path[1:]
            while upstream_path.endswith('//'):
                upstream_path = upstream_path[0:-1]


            self.proxy_pass = 'https://'+ proxy_pass + upstream_path
            self.upstream_host = upstream_host
            self.upstream_context_root = upstream_path
            self.upstream_port = upstream_port
            self.upstream_timeout = upstream_timeout
            self.upstream_timeout_tries = upstream_timeout_tries
            self.upstream_upload_file_size = upstream_upload_file_size
            self.sticky = sticky
            self.disable_chunked_encoding = disable_chunked_encoding

        def __repr__(self):
            rtn = 'Location<'
            rtn += 'location=%s,' % self.location
            rtn += 'proxy_pass=%s,' % self.proxy_pass
            rtn += 'upstream_host=%s,' % self.upstream_host
            rtn += 'upstream_context_root=%s, ' % self.upstream_context_root
            rtn += 'upstream_port=%s, ' % str(self.upstream_port)
            rtn += 'upstream_timeout=%s, ' % str(self.upstream_timeout)
            rtn += 'upstream_timeout_tries=%s, ' % str(self.upstream_timeout_tries)
            rtn += 'upstream_upload_file_size=%s, ' % str(self.upstream_upload_file_size)
            rtn += 'sticky=%s, ' % str(self.sticky)
            rtn += 'disable_chunked_encoding=%s, ' % str(self.disable_chunked_encoding)
            rtn += '>'
            return rtn

    def __init__(self, kz, ac, logger):
        self.kz = kz
        self.ac = ac
        self._sanityCheck = {} #UserFacingUrlPrefix: (upstream#,upstreamPath)
        self._upstreams = {}
        self._servers = {}
        self._serversWithSpecializedCerts = set()
        self._redirects = {}
        self._logger = logger
        self._newSslDir = None

    def _deserializeUpstreamServerRegistration(self, serialized):
        transport = TTransport.TMemoryBuffer(serialized)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        registration = UpstreamServerRegistration()
        registration.read(protocol)
        self._logger.info("zookeeper contains the registration: %s" % (registration))
        return registration

    def _addUpstreamAndServer(self,upstream_number,registration):
        upstream_group_name = 'server'+str(upstream_number)
        upstream_name = registration.UpstreamHostAndPort
        upstream_timeout = registration.timeout
        upstream_timeout_tries = registration.timeoutTries
        upstream_upload_file_size = registration.uploadFileSize
        server_name = registration.UserFacingUrlPrefix.split('/',1)[0]
        loc = self.Location(registration.UserFacingUrlPrefix.split('/',1)[1], upstream_group_name, server_name, registration.UpstreamPath, upstream_name.split(':',1)[0], upstream_name.split(':',1)[1], upstream_timeout, upstream_timeout_tries, upstream_upload_file_size, registration.sticky, registration.disableChunkedTransferEncoding)

        name_to_resolve, port_to_use = upstream_name.split(':',1)
        try:
            #try to resolve the upstream name
            socket.gethostbyname(name_to_resolve)

            if upstream_group_name not in self._upstreams:
                self._upstreams[upstream_group_name] = {'location':loc.location,
                                                        'upstreams':[],
                                                        'sticky':bool(loc.sticky or False),
                                                        'timeout':int(loc.upstream_timeout or 0),
                                                        'timeout_tries':int(loc.upstream_timeout_tries or 0)
                                                       }
            self._upstreams[upstream_group_name]['upstreams'].append(upstream_name)

        except Exception as e:
            self._logger.error("Exception (%s) resolving upstream %s. Dropping that upstream path [%s:%s]. Location %s will not be configured unless it has other (valid) upstreams" % (str(e), name_to_resolve, loc.upstream_host, loc.upstream_port, loc.location))
            #remove from local upstream cache
            if upstream_group_name in self._upstreams:
                del self._upstreams[upstream_group_name]
            #remove from zookeeper
            try:
                self.kz.delete(ezRPKazoo.KZCONFLOC + '/' + ezRPRegistration.getNodeName(registration))
                self.kz.set(ezRPKazoo.KZWATCHLOC, str(gConfig.current_milli_time()))
            except NoNodeError:
                #node didn't exist before
                pass
            except Exception as e:
                self._logger.error('Exception in removing unresolved registration: %s' % str(e))
                raise

        self._logger.info('Configuring Location %s' % str(loc))

        if server_name not in self._servers:
            self._servers[server_name] = {}
        self._servers[server_name][loc.location] = loc

        self._serversWithSpecializedCerts.discard(server_name)
        if self.kz.exists(ezRPKazoo.KZSSLCONFLOC + '/' + server_name):
            if os.path.isfile(os.path.join(self._newSslDir, server_name + '.crt')) and \
               os.path.isfile(os.path.join(self._newSslDir, server_name + '.key')):
                self._serversWithSpecializedCerts.add(server_name)
            else:
                self._logger.error('Certs for configured %s server are not present in %s. Registration will use defaults' % (server_name, gConfig.ssl_server_certs))

        if server_name not in self._redirects:
            self._redirects[server_name] = {}
        if loc.location not in self._redirects[server_name]:
            self._redirects[server_name][loc.location] = []
        self._redirects[server_name][loc.location].append((loc.upstream_host,loc.upstream_port))


    def _addRpEntry(self,registration):
        if registration.UserFacingUrlPrefix not in self._sanityCheck:
            current = self.Sanity(len(self._sanityCheck), registration.UpstreamPath)
            self._sanityCheck[registration.UserFacingUrlPrefix] = current
            self._addUpstreamAndServer(current.UpstreamNumber,registration)
        else:
            current = self._sanityCheck[registration.UserFacingUrlPrefix]
            if current.UpstreamPath == registration.UpstreamPath:
                self._addUpstreamAndServer(current.UpstreamNumber,registration)
            else:
                log("Error registering %s. It's UpstreamPath does not match %s" % (str(registration),self.UpstreamPath))


    def _generateConfigFileContents(self):
        text_array = []

        #configure common http variables for all servers and upstreams
        text_array.append("\nssl on;")
        text_array.append("\nssl_certificate %s;" % (gConfig.ssl_certfile))
        text_array.append("\nssl_certificate_key %s;" % (gConfig.ssl_keyfile))
        text_array.append("\nssl_session_timeout 5m;")
        text_array.append("\nssl_protocols  SSLv3 TLSv1 TLSv1.1 TLSv1.2;")
        text_array.append("\nssl_ciphers  HIGH:!aNULL:!MD5;")
        text_array.append("\nssl_prefer_server_ciphers on;")
        text_array.append("\nssl_verify_client on;")
        text_array.append("\nssl_client_certificate %s;" % (gConfig.ssl_cafile))
        text_array.append("\nssl_verify_depth %s;" % (gConfig.max_ca_depth))
        if os.path.isfile(gConfig.ssl_crl_file):
            text_array.append("\n\tssl_crl %s;" % (gConfig.ssl_crl_file))

        text_array.append("\n\n")

        #configure upstream server blocks
        for k,v in self._upstreams.iteritems():
            text_array.append("upstream %s {\n" % (k))
            if v['sticky']:
                text_array.append("\tsticky name=ezb_upstream_%s path=%s secure;\n" % (hashlib.sha224(v['location']).hexdigest(), v['location']))
            for server in v['upstreams']:
                text_array.append("\tserver %s " % (server))
                if int(v['timeout_tries']) >= 1:
                    text_array.append(" max_fails=%d" % (v['timeout_tries']))
                # Check if upstream timeout is within limits 10.. 120 inclusive.
                if  10 <= int(v['timeout']) <= 120:
                    text_array.append(" fail_timeout=%ds" % (v['timeout']))
                text_array.append(";\n") 
            text_array.append("}\n")

        text_array.append("\n")

        #configure server blocks
        text_array.append("server {\n\tlisten %s:%s;\n\tssl off;\n\treturn 301 https://$host$request_uri;\n}\n\n" % (gConfig.external_hostname,gConfig.http_port))
        for server, locations in sorted(self._servers.iteritems(), reverse=True, key=lambda tuple: sorted(tuple[1].values(), reverse=True, key=attrgetter('location'))[0].location):
            #get server & location from self._servers sorted based on the values stored in location field of the first Location object (sorted) for a server
            #this allows us to list the most descriptive server location first

            extra_listen_directives = ''

            if gConfig.trustedLoadBalancers is not None:
                extra_listen_directives = ' proxy_protocol'

            text_array.append("server {\n\tlisten %s:%s%s;" % (gConfig.external_hostname,gConfig.https_port,extra_listen_directives))
            text_array.append("\n\tserver_name %s;" % server)

            if gConfig.trustedLoadBalancers is not None:
                for elb in gConfig.trustedLoadBalancers.split(','):
                    text_array.append("\n\tset_real_ip_from %s;" % elb.strip())
                text_array.append("\n\treal_ip_header proxy_protocol;")

            text_array.append("\n");

            if server in self._serversWithSpecializedCerts:
                text_array.append("\n\tssl_certificate %s.crt;" % os.path.join(gConfig.ssl_server_certs, server))
                text_array.append("\n\tssl_certificate_key %s.key;" % os.path.join(gConfig.ssl_server_certs, server))

            text_array.append("\n\n")

            for unused,location_details in locations.iteritems():
                text_array.append("\tlocation %s {\n" % (location_details.location))

                if location_details.location == '/ezfrontend/':
                    text_array.append("\t\taccess_log %s/http_access.log admin;" % gConfig.logDirectory)

                upload_file_size = int(location_details.upstream_upload_file_size or 0)
                if upload_file_size:
                    text_array.append("\t\tclient_max_body_size %dM;\n" %(upload_file_size))

                if location_details.disable_chunked_encoding:
                    text_array.append("\t\tchunked_transfer_encoding off;\n")

                # We are using the nginx map directive
                # in nginx.conf file to send connection header field to proxy server if 
                # there is a presence of the upgrade field in the client. No need of a flag
                # for WebSocket connection
                text_array.append("\t\tproxy_http_version 1.1;\n")
                text_array.append("\t\tproxy_set_header Upgrade $http_upgrade;\n")
                text_array.append("\t\tproxy_set_header Connection $connection_upgrade;\n")

                if gConfig.trustedLoadBalancers is not None:
                    text_array.append("\t\tproxy_set_header Ofe-Elastic-Load-Balancer-IP $remote_addr;\n")
                    text_array.append("\t\tproxy_set_header X-Real-IP $proxy_protocol_addr;\n")
                else:
                    text_array.append("\t\tproxy_set_header X-Real-IP $remote_addr;\n")

                text_array.append("\t\tproxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
                text_array.append("\t\tproxy_set_header X-client-cert-s-dn $ssl_client_s_dn;\n")
                text_array.append("\t\tproxy_set_header X-NginX-Proxy true;\n")
                text_array.append("\t\tproxy_set_header ezb_verified_user_info $ezb_verified_user_info;\n")
                text_array.append("\t\tproxy_set_header ezb_verified_signature $ezb_verified_signature;\n")
                text_array.append("\t\tproxy_set_header ezb_user_info_json $ezb_user_info_json;\n")
                text_array.append("\t\tproxy_set_header ezb_user_info_json_signature $ezb_user_info_json_signature;\n")
                text_array.append("\t\tproxy_set_header X-Original-Request $request_uri;\n")
                text_array.append("\t\tproxy_set_header X-Original-Uri $uri;\n")
                text_array.append("\t\tproxy_set_header X-Upstream-Context-Root %s;\n" % (location_details.upstream_context_root))

                # Host should be change to be the original host once we no longer use OpenShift
                text_array.append("\t\tproxy_set_header Host xxx;\n")#%s;\n" % (location_details.upstream_host))
                text_array.append("\t\tproxy_set_header X-Original-Host $http_host;\n")
                text_array.append("\t\tproxy_pass %s;\n" % (location_details.proxy_pass))
                #TODO: configure different certs for different locations
                text_array.append("\t\t#proxy_ssl_certificate %s;\n" % (gConfig.ez_certfile))
                text_array.append("\t\t#proxy_ssl_certificate_key %s;\n" % (gConfig.ez_keyfile))
                text_array.append("\t\t#proxy_ssl_client_certificate %s;\n" % (gConfig.ez_cafile))
                text_array.append("\t\tproxy_redirect default;\n")

                for redir in self._redirects[server][location_details.location]:
                    text_array.append("\n")
                    text_array.append("\t\tproxy_redirect https://%s%s %s;\n" % (redir[0],location_details.upstream_context_root, location_details.location))
                    text_array.append("\t\tproxy_redirect https://%s:%s%s %s;\n" % (redir[0], redir[1], location_details.upstream_context_root, location_details.location))
                    text_array.append("\t\tproxy_redirect http://%s%s %s;\n" % (redir[0], location_details.upstream_context_root, location_details.location))
                    text_array.append("\t\tproxy_redirect http://%s:%s%s %s;\n" % (redir[0], redir[1], location_details.upstream_context_root, location_details.location))
                    text_array.append("\n")
                text_array.append("\t}\n\n")
            text_array.append("}\n\n")
        return ''.join(text_array)

    def _generateConfigFile(self):
        text = self._generateConfigFileContents()
        filename = os.path.join(gConfig.confdDirectory,'servers.conf')
        with open(filename,'w') as config_file:
            config_file.write(text)

    def _reconfigureNginx(self):
        # os.kill is a misnomer -- only way to send a signal in python
        self._logger.info("SIGNALING NGINX TO RECONFIGURE")
        try:
            os.kill(ezRPNginx.get_nginx_master_pid(), signal.SIGHUP)
        except IOError as e:
            self._logger.warn(str(e))

    def _getSslFiles(self):
        curssldir = os.readlink(gConfig.ssl_server_certs)
        self._newSslDir = choice([x for x in gConfig.ssl_server_certs_dirs if x != curssldir])
        shutil.rmtree(self._newSslDir)
        os.mkdir(self._newSslDir, 0700)
        for serverName in self.kz.get_children(ezRPKazoo.KZSSLCONFLOC):
            try:
                try:
                    certContents, keyContents = self.ac.get(serverName)
                except OpenSSL.crypto.Error as ex:
                    self._logger.error("SSL Exception in getting cert contents: %s" % ex)
                    raise
                if certContents is None or keyContents is None:
                    self._logger.warn("Read empty certificate or key contents for %s" % serverName)
                    continue
                with open(os.path.join(self._newSslDir, serverName + '.crt'), 'w') as file:
                    file.write(certContents)
                    os.chmod(file.name, stat.S_IRUSR)
                with open(os.path.join(self._newSslDir, serverName + '.key'), 'w') as file:
                    file.write(keyContents)
                    os.chmod(file.name, stat.S_IRUSR)
            except Exception as e:
                self._logger.error("Exception in creating SSL certs for %s: %s" % (serverName, str(e)))


    def configure(self):
        last_watch = self.kz.get(ezRPKazoo.KZWATCHLOC)[0]
        self._logger.info("Configuring Nginx with WATCH triggered with %s" % last_watch)

        # get ssl files before generating nginx conf files
        self._getSslFiles()

        # get list of entries
        rpEntries = self.kz.get_children(ezRPKazoo.KZCONFLOC)
        for rpEntry in rpEntries:
            serializedRegistration = self.kz.get(ezRPKazoo.KZCONFLOC+'/'+rpEntry)
            registration = self._deserializeUpstreamServerRegistration(serializedRegistration[0])
            self._addRpEntry(registration)
        self._generateConfigFile()

        #update ssl certs directory link before reconfiguring nginx
        subprocess.call(['ln', '-sTf', self._newSslDir, gConfig.ssl_server_certs])

        self._reconfigureNginx()

    def getAllRegistrations(self):
        rpEntries = self.kz.get_children(ezRPKazoo.KZCONFLOC)
        rtn = []
        for rpEntry in rpEntries:
            serializedRegistration = self.kz.get(ezRPKazoo.KZCONFLOC+'/'+rpEntry)
            registration = self._deserializeUpstreamServerRegistration(serializedRegistration[0])
            rtn.append(registration)
        return rtn



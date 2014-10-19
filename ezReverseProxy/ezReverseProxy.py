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

from gevent import monkey
monkey.patch_all()
import sys
import os
import gevent
import logging

import ezdiscovery
from modules import ezRPNginx
from modules import ezRPParser
from modules import ezRPService
from modules import ezRPConfig as gConfig

from ezconfiguration.EzConfiguration import EzConfiguration
from ezconfiguration.helpers import ZookeeperConfiguration, SystemConfiguration
from ezconfiguration.loaders.PropertiesConfigurationLoader import PropertiesConfigurationLoader
from ezconfiguration.loaders.DirectoryConfigurationLoader import DirectoryConfigurationLoader
from ezconfiguration.constants.EzBakePropertyConstants import EzBakePropertyConstants
from ezconfiguration.security.CryptoImplementations import SharedSecretTextCryptoImplementation


logger = logging.getLogger('ofe_control')
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')


def log(arg):
    print(arg)

def getEzSecurityServers():
    rtn = []
    ezdiscovery.connect(gConfig.zk)
    endpoints = ezdiscovery.get_common_endpoints('EzbakeSecurityService')
    ezdiscovery.disconnect()
    for endpoint in endpoints:
        name,port = endpoint.split(':',1)
        rtn.append((name,port))
    return rtn

def getEzProperties():
    #load default configurations
    config = EzConfiguration()
    logger.info("loaded default ezconfiguration properties")

    #load configuration overrides
    overrideLoader = DirectoryConfigurationLoader(gConfig.ezconfig_dir)
    config = EzConfiguration(PropertiesConfigurationLoader(config.getProperties()), overrideLoader)
    logger.info("loaded property overrides")

    #load cryptoImpl
    cryptoImpl = SystemConfiguration(config.getProperties()).getTextCryptoImplementer()
    if not isinstance(cryptoImpl, SharedSecretTextCryptoImplementation):
        logger.warn("Couldn't get a SharedSecretTextCryptoImplementation. Is the EZB shared secret set properly?")

    return config.getProperties(cryptoImpl)


if __name__ == '__main__':
    parser = ezRPParser.setupParser()
    args = parser.parse_args()

    # we're going to run everything from within this packaged application
    # so we need to find our own path
    print os.getpid()

    import logging.handlers
    wfh = logging.handlers.WatchedFileHandler(os.path.join(gConfig.logDirectory,'ofe_control.log'))
    wfh.setLevel(logging.INFO)
    wfh.setFormatter(formatter)
    logger.addHandler(wfh)

    gConfig.ezproperties = getEzProperties()
    if args.external_hostname is not None:
        gConfig.external_hostname = args.external_hostname
    else:
        gConfig.external_hostname = gConfig.ezproperties['external_hostname']
    if args.internal_hostname is not None:
        gConfig.internal_hostname = args.internal_hostname
    else:
        gConfig.internal_hostname = gConfig.ezproperties['internal_hostname']
    if args.zookeepers is not None:
        gConfig.zk = args.zookeepers
    else:
        gConfig.zk = ZookeeperConfiguration(gConfig.ezproperties).getZookeeperConnectionString()
    if args.port is not None:
        gConfig.thriftPort = args.port
    else:
        gConfig.thriftPort = gConfig.ezproperties['ofe.port']

    gConfig.nginx_worker_username = gConfig.ezproperties['ofe.nginx_worker_username']
    gConfig.https_port = gConfig.ezproperties['ofe.https_port']
    gConfig.http_port = gConfig.ezproperties['ofe.http_port']
    gConfig.max_ca_depth = gConfig.ezproperties['ofe.max_ca_depth']

    if 'ofe.crl_file' in gConfig.ezproperties and gConfig.ezproperties['ofe.crl_file'] is not None:
        gConfig.ssl_crl_file = gConfig.ezproperties['ofe.crl_file']

    gConfig.trustedLoadBalancers = gConfig.ezproperties.get('trusted.elastic.load.balancers');


    # Drop the parsed argument dictionary into the global config object
    gConfig.args = args

    if args.no_clean_on_start:
        # simply clean up the config and log directories for this instance
        ezRPNginx.nginx_cleanup_self()
    else:
        # shut down all instances of nginx on this box and clean the 
        # config and log directories for this instance
        ezRPNginx.nginx_cleanup()

    # do the basic setup
    ezRPNginx.nginx_basesetup(logger)
    
    ezs = ezRPService.EzReverseProxyService(logger)
    ezs.run()
    
    ezRPNginx.nginx_cleanup_self(masterPID=ezRPNginx.get_nginx_master_pid())


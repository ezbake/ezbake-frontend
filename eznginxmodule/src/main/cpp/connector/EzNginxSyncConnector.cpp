/*   Copyright (C) 2013-2014 Computer Sciences Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. */

/*
 * EzNginxConnector.cpp
 *
 *  Created on: May 14, 2014
 *      Author: oarowojolu
 */

#include <ezbake/eznginx/connector/EzNginxSyncConnector.h>
#include "ezsecurity_types.h"

namespace ezbake { namespace eznginx { namespace connector {

log4cxx::LoggerPtr const EzNginxSyncConnector::LOG = log4cxx::Logger::getLogger("::ezbake::eznginx::connector::EzNginxSyncConnector");

using ::ezbake::base::thrift::EzSecurityPrincipal;
using ::ezbake::base::thrift::EzSecurityTokenJson;
using ::ezbake::base::thrift::TokenRequest;
using ::ezsecurity::ProxyTokenRequest;
using ::ezsecurity::ProxyTokenResponse;
using ::ezbake::ezconfiguration::helpers::ApplicationConfiguration;


EzNginxSyncConnector::EzNginxSyncConnector(const ::ezbake::ezconfiguration::EZConfiguration& config, const ::std::string& configNamespace)
    : _configNamespace(configNamespace), _configuration(config) {}


EzNginxConnectorInterface::AuthenticationData EzNginxSyncConnector::authenticateUser(const ::ezbake::base::thrift::X509Info& x509Info) {
    EzNginxConnectorInterface::AuthenticationData retVal;

    if (!_securityClient) {
        initialize();
    }

    //generate requests
    ProxyTokenRequest proxyRequest = generateProxyTokenRequest(x509Info,
            _appConfig->getSecurityID(), _securityClient->getSecurityConfig());
    TokenRequest jsonRequest = generateTokenRequest(x509Info, _appConfig->getSecurityID(),
            _securityClient->getSecurityConfig());

    try {
        LOG4CXX_INFO(LOG, "attempting to authenticate user {" << x509Info.subject << "} with security service");
        ProxyTokenResponse proxyResponse = _securityClient->fetchProxyToken(proxyRequest);

        if (hasAuthenticationExpired(proxyResponse)) {
            LOG4CXX_ERROR(LOG, "Authentication error. Received expired Principal data from security service.");
            ::ezbake::base::thrift::EzSecurityTokenException ex;
            ex.message = "Principal received from security service has expired";
            BOOST_THROW_EXCEPTION(ex);
        }
        retVal.userDN = x509Info.subject;
        retVal.proxyTokenString = proxyResponse.token;
        retVal.proxyTokenSignature = proxyResponse.signature;

        EzSecurityTokenJson jsonResponse = _securityClient->fetchUserJson(jsonRequest);
        retVal.jsonString= jsonResponse.json;
        retVal.jsonSignature = jsonResponse.signature;

    } catch(const ::ezbake::base::thrift::EzSecurityTokenException &ex) {
        std::string message = "Internal Error. EzSecurityTokenException: " + ex.message;
        LOG4CXX_ERROR(LOG, message);
        BOOST_THROW_EXCEPTION(::apache::thrift::TException(message));
    } catch(const ::ezsecurity::AppNotRegisteredException &ex) {
        std::string message = "Internal Error. AppNotRegisteredException: " + ex.message;
        LOG4CXX_ERROR(LOG, message);
        BOOST_THROW_EXCEPTION(::apache::thrift::TException(message));
    } catch(const ::ezsecurity::UserNotFoundException &ex) {
        std::string message = "User Not Found (or external user database down): " + ex.message;
        LOG4CXX_ERROR(LOG, message);
        BOOST_THROW_EXCEPTION(::apache::thrift::TException(message));
    } catch(const ::apache::thrift::TException &ex) {
        std::string message = "Internal Error. Generic Thrift Error:  ";
        LOG4CXX_ERROR(LOG, message + boost::diagnostic_information(ex));
        message += ex.what();
        BOOST_THROW_EXCEPTION(::apache::thrift::TException(message));
    } catch(const ::std::exception &ex) {
        std::string message = "Internal Error. Generic STD Exception: ";
        LOG4CXX_ERROR(LOG, message + boost::diagnostic_information(ex));
        message += ex.what();
        BOOST_THROW_EXCEPTION(std::runtime_error(message));
    }

    LOG4CXX_INFO(LOG, "authenticated user {" << x509Info.subject << "} with security service");
    return retVal;
}


void EzNginxSyncConnector::initialize() {
    if (_securityClient) {
        LOG4CXX_WARN(LOG, "eznginx connector already initialized. Reinitializing");
        _securityClient.reset();
    }

    LOG4CXX_INFO(LOG, "initializing eznginx connector");

    try {
        _appConfig = ApplicationConfiguration::fromConfiguration(_configuration, _configNamespace);
        _securityClient = ::boost::make_shared< ::ezbake::security::client::SyncClient>(_configuration, _configNamespace);
    } catch (const std::exception &ex) {
        LOG4CXX_ERROR(LOG, "error in initializing eznginx connector: " + boost::diagnostic_information(ex));
        throw;
    }
}

}}} //ezbake::eznginx::connector

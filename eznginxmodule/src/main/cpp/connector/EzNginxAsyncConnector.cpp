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
 * EzNginxAsyncConnector.cpp
 *
 *  Created on: Jun 5, 2014
 *      Author: oarowojolu
 */

#include <ezbake/eznginx/connector/EzNginxAsyncConnector.h>
#include "ezsecurity_types.h"

namespace ezbake { namespace eznginx { namespace connector {

log4cxx::LoggerPtr const EzNginxAsyncConnector::LOG = log4cxx::Logger::getLogger("::ezbake::eznginx::connector::EzNginxAsyncConnector");

using ::ezbake::base::thrift::EzSecurityPrincipal;
using ::ezbake::base::thrift::EzSecurityTokenJson;
using ::ezsecurity::ProxyTokenRequest;
using ::ezsecurity::ProxyTokenResponse;
using ::ezbake::base::thrift::TokenRequest;
using ::ezbake::security::core::EzSecurityTokenUtils;
using ::ezbake::ezconfiguration::helpers::ApplicationConfiguration;


EzNginxAsyncConnector::EzNginxAsyncConnector(const ::ezbake::ezconfiguration::EZConfiguration& config, const std::string& configNamespace)
    : _configNamespace(configNamespace), _configuration(config) {}


::boost::optional<EzNginxConnectorInterface::AuthenticationData>
EzNginxAsyncConnector::authenticateUser(const AuthenticateCallback& cb, const ::ezbake::base::thrift::X509Info& x509Info) {
    ::boost::shared_ptr<AuthenticationData> authData;
    ProxyTokenRequest proxyRequest = generateProxyTokenRequest(x509Info,
            _appConfig->getSecurityID(), _securityClient->getSecurityConfig());

    LOG4CXX_INFO(LOG, "Requesting ProxyToken for user {" << x509Info.subject << "}.");

    ::boost::optional<ProxyTokenResponse> proxyTokenOpt =
            _securityClient->fetchProxyToken(::boost::bind(&EzNginxAsyncConnector::handleProxyTokenCallback,
                                                           this, _1, _2, cb, x509Info), proxyRequest);

    if (proxyTokenOpt) {
        LOG4CXX_INFO(LOG, "got ProxyTokenResponse user {" << x509Info.subject << "} from cache. "
                "Credentials expire at " << EzSecurityTokenUtils::getProxyTokenResponseExpiration(*proxyTokenOpt));

        authData = ::boost::make_shared<AuthenticationData>();
        authData->userDN = x509Info.subject;
        authData->proxyTokenString = proxyTokenOpt->token;
        authData->proxyTokenSignature = proxyTokenOpt->signature;


        TokenRequest tokenRequest = generateTokenRequest(x509Info, _appConfig->getSecurityID(),
                _securityClient->getSecurityConfig());
        ::boost::optional<EzSecurityTokenJson> jsonOpt =
                _securityClient->fetchUserJson(::boost::bind(&EzNginxAsyncConnector::handleUserJsonCallback,
                                                             this, _1, _2, cb, authData), tokenRequest);

        if (jsonOpt) {
            LOG4CXX_INFO(LOG, "got EzSecurityTokenJson user {" << authData->userDN << "} from cache. "
                    "Credentials expire at " << EzSecurityTokenUtils::getEzSecurityTokenJsonExpiration(*jsonOpt));

            authData->jsonString = jsonOpt->json;
            authData->jsonSignature = jsonOpt->signature;

            LOG4CXX_INFO(LOG, "Successfully authenticated user {" << authData->userDN << "} from cache.");
            return ::boost::optional<EzNginxConnectorInterface::AuthenticationData>(*authData);
        }
    }

    LOG4CXX_DEBUG(LOG, "Could not generate AuthenticationData from cache. Async dispatch pending");
    return ::boost::none;
}


void EzNginxAsyncConnector::initialize() {
    if (_securityClient) {
        LOG4CXX_WARN(LOG, "eznginx connector already initialized. Reinitializing");
        _securityClient.reset();
    }

    LOG4CXX_INFO(LOG, "initializing eznginx connector");

    try {
        _appConfig = ApplicationConfiguration::fromConfiguration(_configuration, _configNamespace);
        _securityClient = ::boost::make_shared< ::ezbake::security::client::AsyncClient>(_configuration,
                _configNamespace, "system_services");
    } catch (const std::exception &ex) {
        LOG4CXX_ERROR(LOG, "error in initializing eznginx connector: " + boost::diagnostic_information(ex));
        throw;
    }
}


void EzNginxAsyncConnector::handleProxyTokenCallback(const ::boost::shared_ptr< ::std::exception >& err,
        const ::boost::shared_ptr<ProxyTokenResponse>& proxyTokenRsp, const AuthenticateCallback& cb,
        const ::ezbake::base::thrift::X509Info& x509Info) {
    if (err) {
        LOG4CXX_ERROR(LOG, "Authentication error. Couldn't get ProxyTokenResponse data: " << err->what());
        cb(err, ::boost::shared_ptr<AuthenticationData>());
        return;
    }

    try {
        ::boost::shared_ptr<EzNginxConnectorInterface::AuthenticationData> authData =
                ::boost::make_shared<EzNginxConnectorInterface::AuthenticationData>();

        authData->userDN = x509Info.subject;
        authData->proxyTokenString = proxyTokenRsp->token;
        authData->proxyTokenSignature = proxyTokenRsp->signature;

        LOG4CXX_INFO(LOG, "received async call response for User Info {" << authData->userDN << "} from security service. " <<
                          "Dispatching async call to retrieve User Json with security service");

        TokenRequest jsonRequest = generateTokenRequest(x509Info, _appConfig->getSecurityID(),
                _securityClient->getSecurityConfig());

        ::boost::optional<EzSecurityTokenJson> jsonOpt =
                _securityClient->fetchUserJson(::boost::bind(&EzNginxAsyncConnector::handleUserJsonCallback,
                                                             this, _1, _2, cb, authData), jsonRequest);

        if (jsonOpt) {
            LOG4CXX_INFO(LOG, "got EzSecurityTokenJson user {" << authData->userDN << "} from cache. "
                    "Credentials expire at " << EzSecurityTokenUtils::getEzSecurityTokenJsonExpiration(*jsonOpt));

            authData->jsonString = jsonOpt->json;
            authData->jsonSignature = jsonOpt->signature;

            LOG4CXX_INFO(LOG, "Successfully authenticated user {" << authData->userDN << "} from security service/cache."
                    " Invoking nginx auth handler");
            cb(::boost::shared_ptr< ::std::exception >(), authData);
            return;
        }
    } catch (const ::std::exception &ex) {
        LOG4CXX_ERROR(LOG, "Exception in handling ProxyTokenCallback: " << ex.what());
        cb(::boost::make_shared< ::std::runtime_error>(ex.what()),
                ::boost::shared_ptr<AuthenticationData>());
    }
}


void EzNginxAsyncConnector::handleUserJsonCallback(const ::boost::shared_ptr< ::std::exception >& err,
        const ::boost::shared_ptr<EzSecurityTokenJson>& json, const AuthenticateCallback& cb,
        const ::boost::shared_ptr<AuthenticationData>& authData) {
    if (err) {
        LOG4CXX_ERROR(LOG, "Authentication error. Couldn't get UserJson: " << err->what());
        cb(err, ::boost::shared_ptr<AuthenticationData>());
        return;
    }

    try {
        authData->jsonString = json->json;
        authData->jsonSignature = json->signature;

        LOG4CXX_INFO(LOG, "received async call response for User Json {" << authData->userDN
                << "} from security service. Invoking nginx auth handler");

        cb(::boost::shared_ptr< ::std::exception >(), authData);
    } catch (const std::exception &ex) {
        LOG4CXX_ERROR(LOG, "Exception in handling UserJsonCallback: " << ex.what());
        cb(::boost::make_shared< ::std::runtime_error>(ex.what()),
                ::boost::shared_ptr<AuthenticationData>());
    }
}


}}} //ezbake::eznginx::connector

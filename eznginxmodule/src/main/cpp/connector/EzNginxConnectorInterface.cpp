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
 * EzNginxConnectorInterface.cpp
 *
 *  Created on: Aug 7, 2014
 *      Author: oarowojolu
 */

#include <ezbake/eznginx/connector/EzNginxConnectorInterface.h>
#include <ezbake/security/core/CommonUtils.h>
#include <ezbake/security/client/CommonClient.h>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>


namespace ezbake { namespace eznginx { namespace connector {

using ::ezbake::security::core::EzSecurityTokenUtils;
using ::ezbake::base::thrift::ProxyUserToken;
using ::ezsecurity::ProxyTokenResponse;
using ::ezbake::ezconfiguration::helpers::SecurityConfiguration;


::ezbake::base::thrift::TokenRequest EzNginxConnectorInterface::generateTokenRequest(const ::ezbake::base::thrift::X509Info& x509Info,
        const ::std::string& securityId, const SecurityConfiguration& securityConfig) {

    ::ezbake::base::thrift::EzSecurityPrincipal principal;
    principal.principal = x509Info.subject;
    principal.validity.issuer = securityId;
    principal.validity.issuedTo = "EzSecurity";
    principal.validity.notAfter = ::ezbake::security::core::CommonUtils::currentTimeMillis() +
                                  ::ezbake::security::client::CommonClient::PRINCIPAL_EXPIRY;
    principal.validity.signature = "";

    ::ezbake::base::thrift::TokenRequest request;
    request.__set_securityId(securityId);
    request.__set_timestamp(::ezbake::security::core::CommonUtils::currentTimeMillis());
    request.__set_principal(principal);
    request.__set_type(::ezbake::base::thrift::TokenType::USER);
    request.__set_caveats(principal.validity);

    //update signature in TokenRequest.ValidityCaveats
    request.caveats.signature = EzSecurityTokenUtils::tokenRequestSignature(request, securityConfig);

    return request;
}


::ezsecurity::ProxyTokenRequest EzNginxConnectorInterface::generateProxyTokenRequest(const ::ezbake::base::thrift::X509Info& x509Info,
        const ::std::string& securityId, const SecurityConfiguration& securityConfig) {

    ::ezbake::base::thrift::ValidityCaveats validityCaveats;
    validityCaveats.__set_issuer(securityId);
    validityCaveats.__set_issuedTo("");
    validityCaveats.__set_notAfter(::ezbake::security::core::CommonUtils::currentTimeMillis() +
                                   ::ezbake::security::client::CommonClient::PRINCIPAL_EXPIRY);
    validityCaveats.__set_signature("");

    ::ezsecurity::ProxyTokenRequest request;
    request.__set_x509(x509Info);
    request.__set_validity(validityCaveats);

    //update signature
    request.validity.signature = EzSecurityTokenUtils::proxyTokenRequestSignature(request, securityConfig);

    return request;
}


::std::string EzNginxConnectorInterface::convertTimeMillisToStr(int64_t time) {
    ::std::ostringstream ss;
    ss << ::std::setfill('0') << ::std::setw(TIME_STR_WIDTH) << time;
    return ss.str();
}


bool EzNginxConnectorInterface::hasAuthenticationExpired(const ProxyTokenResponse& proxyToken) {
    bool hasExpired = true;
    ::std::stringstream ss(proxyToken.token);
    ::boost::property_tree::ptree pt;

    try {
        ::boost::property_tree::read_json(ss, pt);
    } catch (const ::boost::property_tree::json_parser_error& ex) {
        BOOST_THROW_EXCEPTION(::std::runtime_error("Exception in parsing proxyToken.token JSON: " +
                ::boost::diagnostic_information(ex) + "\nJSON contents:\n" + ss.str()));
    }

    try {
        int64_t expiryTime = pt.get<int64_t>("notAfter");
        hasExpired = (expiryTime < ::ezbake::security::core::CommonUtils::currentTimeMillis());
    } catch (const ::boost::property_tree::ptree_error& ex) {
        BOOST_THROW_EXCEPTION(::std::runtime_error("Exception in determining authentication expiry: " +
                ::boost::diagnostic_information(ex)));
    }
    return hasExpired;
}


bool EzNginxConnectorInterface::hasAuthenticationExpired(const ProxyUserToken& token) {
    return (token.notAfter < ::ezbake::security::core::CommonUtils::currentTimeMillis());
}


}}} // namespace ezbake::eznginx::connector

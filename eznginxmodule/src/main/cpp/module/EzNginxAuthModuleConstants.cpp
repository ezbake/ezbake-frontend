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
 * EzNginxAuthModuleConstants.cpp
 *
 *  Created on: Mar 14, 2014
 *      Author: oarowojolu
 */

#include <ezbake/eznginx/module/EzNginxAuthModule.h>

using namespace ezbake::eznginx;

/**
 * Initialize our static constants
 */

const ngx_command_t EzNginxAuthModuleBase::COMMANDS[] = {

    {
        ngx_string("eznginx_log_props"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(EzNginxAuthModule::ngx_http_eznginx_auth_main_conf_t, log4jPropertyFilePath),
        NULL
    },

    {
        ngx_string("ezconfig_override_dir"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(EzNginxAuthModule::ngx_http_eznginx_auth_main_conf_t, ezConfigOverrideDir),
        NULL
    },

    ngx_null_command
};


const ngx_http_module_t EzNginxAuthModuleBase::MODULE_CONTEXT = {
    EzNginxAuthModule::addEzbVariables,             /* preconfiguration */
    EzNginxAuthModule::initialize,                  /* postconfiguration */
    EzNginxAuthModule::createMainConfiguration,     /* create main configuration */
    EzNginxAuthModule::initMainConfiguration,       /* init main configuration */
    NULL,                                           /* create server configuration */
    NULL,                                           /* merge server configuration */
    NULL,                                           /* create location configuration */
    NULL                                            /* merge location configuration */
};


const EzNginxAuthModuleBase::ngx_module_entry_init_master_func EzNginxAuthModuleBase::INIT_MASTER_HANDLER = NULL;
const EzNginxAuthModuleBase::ngx_module_entry_init_func EzNginxAuthModuleBase::INIT_MODULE_HANDLER = EzNginxAuthModule::initializeModuleCallback;
const EzNginxAuthModuleBase::ngx_module_entry_init_func EzNginxAuthModuleBase::INIT_PROCESS_HANDLER = EzNginxAuthModule::initializeProcessCallback;
const EzNginxAuthModuleBase::ngx_module_entry_init_func EzNginxAuthModuleBase::INIT_THREAD_HANDLER = NULL;
const EzNginxAuthModuleBase::ngx_module_entry_exit_func EzNginxAuthModuleBase::EXIT_THREAD_HANDLER = NULL;
const EzNginxAuthModuleBase::ngx_module_entry_exit_func EzNginxAuthModuleBase::EXIT_PROCESS_HANDLER = NULL;
const EzNginxAuthModuleBase::ngx_module_entry_exit_func EzNginxAuthModuleBase::EXIT_MASTER_HANDLER = NULL;


const ngx_http_variable_t  EzNginxAuthModule::SESSION_VARIABLES[] = {

    { ngx_string("ezb_remote_user"), NULL, EzNginxAuthModule::getEzbVariable,
      (uintptr_t)offsetof(EzNginxAuthModule::ngx_http_eznginx_auth_vars_t, ezb_user_info),
      NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("ezb_verified_user_info"), NULL, EzNginxAuthModule::getEzbVariable,
      (uintptr_t)offsetof(EzNginxAuthModule::ngx_http_eznginx_auth_vars_t, ezb_user_info),
      NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("ezb_verified_signature"), NULL, EzNginxAuthModule::getEzbVariable,
      (uintptr_t)offsetof(EzNginxAuthModule::ngx_http_eznginx_auth_vars_t, ezb_user_signature),
      NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("ezb_user_info_json"), NULL, EzNginxAuthModule::getEzbVariable,
      (uintptr_t)offsetof(EzNginxAuthModule::ngx_http_eznginx_auth_vars_t, ezb_user_info_json),
      NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("ezb_user_info_json_signature"), NULL, EzNginxAuthModule::getEzbVariable,
      (uintptr_t)offsetof(EzNginxAuthModule::ngx_http_eznginx_auth_vars_t, ezb_user_info_json_signature),
      NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};

const ngx_msec_t EzNginxAuthModule::CONNECTOR_POLL_PERIOD = 600;//2*NGX_TIMER_LAZY_DELAY
const int EzNginxAuthModule::CONNECTOR_POLL_MAX_TRIES = 50;
const ::std::string EzNginxAuthModule::CONNECTOR_SERVICENAME = "ofe";
const ::std::string EzNginxAuthModule::CONNECTOR_POLL_PERIOD_KEY = CONNECTOR_SERVICENAME + ".eznginx.auth.poll.period";
const ::std::string EzNginxAuthModule::CONNECTOR_POLL_MAX_TRIES_KEY = CONNECTOR_SERVICENAME + ".eznginx.auth.poll.max.tries";

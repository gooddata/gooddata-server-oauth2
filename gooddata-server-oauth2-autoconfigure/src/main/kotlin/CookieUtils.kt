/*
 * Copyright 2021 GoodData Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.gooddata.oauth2.server

import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest

/**
 * Cookie key for storing serialized [OAuth2AuthorizationRequest].
 */
const val SPRING_SEC_OAUTH2_AUTHZ_RQ = "SPRING_SEC_OAUTH2_AUTHZ_RQ"

/**
 * Cookie key for storing serialized [OAuth2AuthorizedClient].
 */
const val SPRING_SEC_OAUTH2_AUTHZ_CLIENT = "SPRING_SEC_OAUTH2_AUTHZ_CLIENT"

/**
 * Cookie key for storing serialized [OAuth2AuthenticationToken].
 */
const val SPRING_SEC_SECURITY_CONTEXT = "SPRING_SEC_SECURITY_CONTEXT"

/**
 * Cookie key for storing serialized redirect URI.
 */
const val SPRING_REDIRECT_URI = "SPRING_REDIRECT_URI"

/**
 * Cookie key for storing serialized federated identity provider ID.
 */
const val SPRING_EXTERNAL_IDP = "SPRING_EXTERNAL_IDP"

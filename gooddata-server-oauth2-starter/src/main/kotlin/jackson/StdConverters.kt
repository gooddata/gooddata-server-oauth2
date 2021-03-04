/*
 * Copyright 2002-2020 the original author or authors.
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
 *
 * Forked from https://github.com/spring-projects/spring-security/blob/5.4.0/oauth2/oauth2-client/src/main/java/org/springframework/security/oauth2/client/jackson2/StdConverters.java
 */
package com.gooddata.oauth2.server.jackson

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.util.StdConverter
import com.gooddata.oauth2.server.jackson.JsonNodeUtils.findStringValue
import org.springframework.security.oauth2.core.AuthenticationMethod
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.OAuth2AccessToken

/**
 * `StdConverter` implementations.
 *
 * @author Joe Grandja
 * @since 5.3
 */
internal abstract class StdConverters {
    internal class AccessTokenTypeConverter : StdConverter<JsonNode?, OAuth2AccessToken.TokenType?>() {
        override fun convert(jsonNode: JsonNode?): OAuth2AccessToken.TokenType? {
            val value = findStringValue(jsonNode, "value")
            return if (OAuth2AccessToken.TokenType.BEARER.getValue().equals(value, ignoreCase = true)) {
                OAuth2AccessToken.TokenType.BEARER
            } else null
        }
    }

    internal class ClientAuthenticationMethodConverter :
        StdConverter<JsonNode?, ClientAuthenticationMethod?>() {
        @Suppress("ReturnCount")
        override fun convert(jsonNode: JsonNode?): ClientAuthenticationMethod? {
            val value = findStringValue(jsonNode, "value")
            if (ClientAuthenticationMethod.BASIC.getValue().equals(value, ignoreCase = true)) {
                return ClientAuthenticationMethod.BASIC
            }
            if (ClientAuthenticationMethod.POST.getValue().equals(value, ignoreCase = true)) {
                return ClientAuthenticationMethod.POST
            }
            return if (ClientAuthenticationMethod.NONE.getValue().equals(value, ignoreCase = true)) {
                ClientAuthenticationMethod.NONE
            } else null
        }
    }

    @Suppress("DEPRECATION")
    internal class AuthorizationGrantTypeConverter : StdConverter<JsonNode?, AuthorizationGrantType?>() {
        @Suppress("ReturnCount")
        override fun convert(jsonNode: JsonNode?): AuthorizationGrantType? {
            val value = findStringValue(jsonNode, "value")
            if (AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(value, ignoreCase = true)) {
                return AuthorizationGrantType.AUTHORIZATION_CODE
            }
            if (AuthorizationGrantType.IMPLICIT.getValue().equals(value, ignoreCase = true)) {
                return AuthorizationGrantType.IMPLICIT
            }
            if (AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(value, ignoreCase = true)) {
                return AuthorizationGrantType.CLIENT_CREDENTIALS
            }
            return if (AuthorizationGrantType.PASSWORD.getValue().equals(value, ignoreCase = true)) {
                AuthorizationGrantType.PASSWORD
            } else null
        }
    }

    internal class AuthenticationMethodConverter : StdConverter<JsonNode?, AuthenticationMethod?>() {
        @Suppress("ReturnCount")
        override fun convert(jsonNode: JsonNode?): AuthenticationMethod? {
            val value = findStringValue(jsonNode, "value")
            if (AuthenticationMethod.HEADER.getValue().equals(value, ignoreCase = true)) {
                return AuthenticationMethod.HEADER
            }
            if (AuthenticationMethod.FORM.getValue().equals(value, ignoreCase = true)) {
                return AuthenticationMethod.FORM
            }
            return if (AuthenticationMethod.QUERY.getValue().equals(value, ignoreCase = true)) {
                AuthenticationMethod.QUERY
            } else null
        }
    }
}

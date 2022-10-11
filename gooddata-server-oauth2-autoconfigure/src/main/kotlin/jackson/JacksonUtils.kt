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
 * Forked from https://github.com/spring-projects/spring-security/blob/5.4.0/oauth2/oauth2-client/src/main/java/org/springframework/security/oauth2/client/jackson2/JsonNodeUtils.java
 * Forked from https://github.com/spring-projects/spring-security/blob/5.4.0/oauth2/oauth2-client/src/main/java/org/springframework/security/oauth2/client/jackson2/StdConverters.java
 */
package com.gooddata.oauth2.server.jackson

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.util.StdConverter
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType
import org.springframework.security.oauth2.core.OAuth2RefreshToken
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.OidcUserInfo
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser

val mapper: ObjectMapper = ObjectMapper()
    .addMixIn(OAuth2AuthorizationRequest::class.java, OAuth2AuthorizationRequestMixin::class.java)
    .addMixIn(OAuth2RefreshToken::class.java, OAuth2RefreshTokenMixin::class.java)
    .addMixIn(OAuth2AccessToken::class.java, OAuth2AccessTokenMixin::class.java)
    .addMixIn(OAuth2AuthenticationToken::class.java, OAuth2AuthenticationTokenMixin::class.java)
    .addMixIn(DefaultOidcUser::class.java, DefaultOidcUserMixin::class.java)
    .addMixIn(OidcIdToken::class.java, OidcIdTokenMixin::class.java)
    .addMixIn(OidcUserInfo::class.java, OidcUserInfoMixin::class.java)
    .registerModule(JavaTimeModule())

internal val SET_TYPE_REFERENCE = object : TypeReference<Set<String>>() {}
internal val MAP_TYPE_REFERENCE = object : TypeReference<Map<String, Any>>() {}

private val AUTHORIZATION_GRANT_TYPE_CONVERTER = AuthorizationGrantTypeConverter()

internal fun JsonNode.findTextValue(fieldName: String): String? = findValue(fieldName)?.asText()

internal fun JsonNode.authorizationGrantType(): AuthorizationGrantType? =
    AUTHORIZATION_GRANT_TYPE_CONVERTER.convert(findValue("authorizationGrantType"))

internal class AccessTokenTypeConverter : StdConverter<JsonNode, TokenType?>() {
    override fun convert(jsonNode: JsonNode): TokenType? {
        val value = jsonNode.findTextValue("value")
        return if (TokenType.BEARER.equalsString(value)) TokenType.BEARER else null
    }

    private fun TokenType.equalsString(other: String?) = value.equals(other, ignoreCase = true)
}

internal class AuthorizationGrantTypeConverter : StdConverter<JsonNode, AuthorizationGrantType>() {
    override fun convert(jsonNode: JsonNode): AuthorizationGrantType? {
        val value = jsonNode.findTextValue("value")
        @Suppress("DEPRECATION")
        return when {
            AuthorizationGrantType.AUTHORIZATION_CODE.equalsString(value) -> AuthorizationGrantType.AUTHORIZATION_CODE
            AuthorizationGrantType.IMPLICIT.equalsString(value) -> AuthorizationGrantType.IMPLICIT
            AuthorizationGrantType.CLIENT_CREDENTIALS.equalsString(value) -> AuthorizationGrantType.CLIENT_CREDENTIALS
            AuthorizationGrantType.PASSWORD.equalsString(value) -> AuthorizationGrantType.PASSWORD
            else -> null
        }
    }

    private fun AuthorizationGrantType.equalsString(other: String?) = value.equals(other, ignoreCase = true)
}

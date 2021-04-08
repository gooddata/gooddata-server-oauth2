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
 * Forked from https://github.com/spring-projects/spring-security/blob/5.4.0/oauth2/oauth2-client/src/main/java/org/springframework/security/oauth2/client/jackson2/OAuth2AuthorizationRequestDeserializer.java
 */
package com.gooddata.oauth2.server.common.jackson

import com.fasterxml.jackson.core.JsonParseException
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.JsonDeserializer
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest

/**
 * A `JsonDeserializer` for [OAuth2AuthorizationRequest].
 *
 * @author Joe Grandja
 * @since 5.3
 * @see OAuth2AuthorizationRequest
 * @see OAuth2AuthorizationRequestMixin
 */
internal class OAuth2AuthorizationRequestDeserializer : JsonDeserializer<OAuth2AuthorizationRequest>() {
    override fun deserialize(parser: JsonParser, context: DeserializationContext): OAuth2AuthorizationRequest {
        val mapper = parser.codec as ObjectMapper
        val node = mapper.readTree<JsonNode>(parser)

        return when (node.authorizationGrantType()) {
            AuthorizationGrantType.AUTHORIZATION_CODE -> OAuth2AuthorizationRequest.authorizationCode()
            else -> throw JsonParseException(parser, "Invalid authorizationGrantType")
        }
            .authorizationUri(node.findTextValue("authorizationUri"))
            .clientId(node.findTextValue("clientId"))
            .redirectUri(node.findTextValue("redirectUri"))
            .scopes(mapper.convertValue(node.findValue("scopes"), SET_TYPE_REFERENCE))
            .state(node.findTextValue("state"))
            .additionalParameters(
                mapper.convertValue(node.findValue("additionalParameters"), MAP_TYPE_REFERENCE)
            )
            .authorizationRequestUri(node.findTextValue("authorizationRequestUri"))
            .attributes(mapper.convertValue(node.findValue("attributes"), MAP_TYPE_REFERENCE))
            .build()
    }
}

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
package com.gooddata.oauth2.server.jackson

import com.fasterxml.jackson.core.JsonParseException
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.JsonDeserializer
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.util.StdConverter
import com.gooddata.oauth2.server.jackson.JsonNodeUtils.findObjectNode
import com.gooddata.oauth2.server.jackson.JsonNodeUtils.findStringValue
import com.gooddata.oauth2.server.jackson.JsonNodeUtils.findValue
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest.Builder
import java.io.IOException

/**
 * A `JsonDeserializer` for [OAuth2AuthorizationRequest].
 *
 * @author Joe Grandja
 * @since 5.3
 * @see OAuth2AuthorizationRequest
 *
 * @see OAuth2AuthorizationRequestMixin
 */
internal class OAuth2AuthorizationRequestDeserializer : JsonDeserializer<OAuth2AuthorizationRequest?>() {
    @Throws(IOException::class)
    override fun deserialize(parser: JsonParser, context: DeserializationContext?): OAuth2AuthorizationRequest {
        val mapper: ObjectMapper = parser.getCodec() as ObjectMapper
        val root: JsonNode = mapper.readTree(parser)
        return deserialize(parser, mapper, root)
    }

    @Throws(JsonParseException::class)
    private fun deserialize(parser: JsonParser, mapper: ObjectMapper, root: JsonNode): OAuth2AuthorizationRequest {
        val authorizationGrantType: AuthorizationGrantType? = AUTHORIZATION_GRANT_TYPE_CONVERTER
            .convert(findObjectNode(root, "authorizationGrantType"))
        val builder: Builder = getBuilder(parser, authorizationGrantType)
        builder.authorizationUri(findStringValue(root, "authorizationUri"))
        builder.clientId(findStringValue(root, "clientId"))
        builder.redirectUri(findStringValue(root, "redirectUri"))
        builder.scopes(findValue(root, "scopes", JsonNodeUtils.STRING_SET, mapper))
        builder.state(findStringValue(root, "state"))
        builder.additionalParameters(
            findValue(root, "additionalParameters", JsonNodeUtils.STRING_OBJECT_MAP, mapper)
        )
        builder.authorizationRequestUri(findStringValue(root, "authorizationRequestUri"))
        builder.attributes(findValue(root, "attributes", JsonNodeUtils.STRING_OBJECT_MAP, mapper))
        return builder.build()
    }

    @Suppress("DEPRECATION")
    @Throws(JsonParseException::class)
    private fun getBuilder(
        parser: JsonParser,
        authorizationGrantType: AuthorizationGrantType?
    ): OAuth2AuthorizationRequest.Builder {
        if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationGrantType)) {
            return OAuth2AuthorizationRequest.authorizationCode()
        }
        if (AuthorizationGrantType.IMPLICIT.equals(authorizationGrantType)) {
            return OAuth2AuthorizationRequest.implicit()
        }
        throw JsonParseException(parser, "Invalid authorizationGrantType")
    }

    companion object {
        private val AUTHORIZATION_GRANT_TYPE_CONVERTER: StdConverter<JsonNode?, AuthorizationGrantType?> =
            StdConverters.AuthorizationGrantTypeConverter()
    }
}

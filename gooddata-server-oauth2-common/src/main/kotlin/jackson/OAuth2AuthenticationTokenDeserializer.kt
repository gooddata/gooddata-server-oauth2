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
package com.gooddata.oauth2.server.common.jackson

import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.JsonDeserializer
import com.fasterxml.jackson.databind.JsonNode
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser

/**
 * A `JsonDeserializer` for [OAuth2AuthenticationToken].
 *
 * @see OAuth2AuthenticationToken
 * @see OAuth2AuthenticationTokenMixin
 */
internal class OAuth2AuthenticationTokenDeserializer : JsonDeserializer<OAuth2AuthenticationToken>() {
    override fun deserialize(parser: JsonParser, context: DeserializationContext): OAuth2AuthenticationToken {
        val codec = parser.codec
        val node = codec.readTree<JsonNode>(parser)

        val principal = codec.treeToValue(
            node.findValue("principal"), DefaultOidcUser::class.java
        )
        val authorizedClientRegistrationId = node.findTextValue("authorizedClientRegistrationId")
        return OAuth2AuthenticationToken(principal, emptyList(), authorizedClientRegistrationId)
    }
}

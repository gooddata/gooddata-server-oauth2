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
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority

/**
 * A `JsonDeserializer` for [DefaultOidcUser].
 *
 * @see DefaultOidcUser
 * @see DefaultOidcUserMixin
 */
internal class DefaultOidcUserDeserializer : JsonDeserializer<DefaultOidcUser>() {
    override fun deserialize(parser: JsonParser, context: DeserializationContext): DefaultOidcUser {
        val codec = parser.codec
        val node = codec.readTree<JsonNode>(parser)

        val idToken = codec.treeToValue(node.findValue("idToken"), OidcIdToken::class.java)
        return DefaultOidcUser(listOf(OidcUserAuthority(idToken)), idToken)
    }
}

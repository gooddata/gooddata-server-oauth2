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
package com.gooddata.oauth2.server.jackson

import net.javacrumbs.jsonunit.JsonAssert.assertJsonEquals
import net.javacrumbs.jsonunit.core.Configuration
import net.javacrumbs.jsonunit.core.Option
import net.javacrumbs.jsonunit.core.util.ResourceUtils.resource
import org.junit.jupiter.api.Test
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import strikt.api.expectThat
import strikt.assertions.isA
import strikt.assertions.isEqualTo

internal class OAuth2AuthenticationTokenTest {

    @Test
    fun `deserialization works`() {
        val body = resource("oauth2_authentication_token.json").readText()

        val obj = mapper.readValue(body, OAuth2AuthenticationToken::class.java)

        expectThat(obj) {
            get(OAuth2AuthenticationToken::getAuthorizedClientRegistrationId)
                .isEqualTo("localhost")
            get(OAuth2AuthenticationToken::getPrincipal).isA<OidcUser>().and {
                get(OidcUser::getIdToken)
                    .get(OidcIdToken::getTokenValue).isEqualTo("tokenValue")
            }
        }
    }

    @Test
    fun `serialization works`() {
        val body = resource("oauth2_authentication_token.json").readText()
        val obj = mapper.readValue(body, OAuth2AuthenticationToken::class.java)
        assertJsonEquals(
            resource("oauth2_authentication_token.json").readText(),
            mapper.writeValueAsString(obj),
            Configuration.empty().withOptions(Option.IGNORING_ARRAY_ORDER)
        )
    }
}

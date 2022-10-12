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
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.OAuth2RefreshToken
import strikt.api.expectThat
import strikt.assertions.contains
import strikt.assertions.isEqualTo
import strikt.assertions.isNull
import java.time.Instant

internal class SimplifiedOAuth2AuthorizedClientTest {

    @Test
    fun `deserialization works`() {
        val body = resource("simplified_oauth2_authorized_client.json").readText()

        val obj = mapper.readValue(body, SimplifiedOAuth2AuthorizedClient::class.java)
        expectThat(obj) {
            get(SimplifiedOAuth2AuthorizedClient::principalName)
                .isEqualTo("localhost|5f6dee2c5924f0006f077df0")
            get(SimplifiedOAuth2AuthorizedClient::registrationId)
                .isEqualTo("localhost")
        }
        expectThat(obj.accessToken) {
            get(OAuth2AccessToken::getTokenType)
                .isEqualTo(OAuth2AccessToken.TokenType.BEARER)
            get(OAuth2AccessToken::getScopes)
                .contains("openid", "profile", "email", "address", "phone", "offline_access")
            get(OAuth2AccessToken::getExpiresAt)
                .isEqualTo(Instant.parse("2020-11-03T20:24:47.127795Z"))
            get(OAuth2AccessToken::getIssuedAt)
                .isEqualTo(Instant.parse("2020-11-02T20:24:47.127795Z"))
            get(OAuth2AccessToken::getTokenValue)
                .isEqualTo("kvArAU1BWUmSiNvW5u3qP1y1Nvf4X-Qn")
        }
        expectThat(obj.refreshToken!!) {
            get(OAuth2RefreshToken::getExpiresAt)
                .isNull()
            get(OAuth2RefreshToken::getIssuedAt)
                .isEqualTo(Instant.parse("2020-11-02T20:24:47.127795Z"))
            get(OAuth2RefreshToken::getTokenValue)
                .isEqualTo("taiiBdgE3VqlhuINWnqM2zwCBzFIbbSx3kaQeg1Wwfa5D")
        }
    }

    @Test
    fun `serialization works`() {
        val body = resource("simplified_oauth2_authorized_client.json").readText()
        val obj = mapper.readValue(body, SimplifiedOAuth2AuthorizedClient::class.java)
        assertJsonEquals(
            resource("simplified_oauth2_authorized_client.json").readText(),
            mapper.writeValueAsString(obj),
            Configuration.empty().withOptions(Option.IGNORING_ARRAY_ORDER)
        )
    }
}

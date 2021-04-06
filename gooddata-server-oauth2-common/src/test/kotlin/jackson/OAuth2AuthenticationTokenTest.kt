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
                    .get(OidcIdToken::getTokenValue).isEqualTo(
                        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im1qTWNkSzZtRVJ2Sjl3WDZhWGxVSyJ9." +
                            "eyJuaWNrbmFtZSI6ImpvZSIsIm5hbWUiOiJqb2VAZXhhbXBsZS5jb20iLCJwaWN0dXJlIjoiaHR0cHM6L" +
                            "y9zLmdyYXZhdGFyLmNvbS9hdmF0YXIvZjViOGZiNjBjNjExNjMzMWRhMDdjNjViOTZhOGExZDE_cz00OD" +
                            "Amcj1wZyZkPWh0dHBzJTNBJTJGJTJGY2RuLmF1dGgwLmNvbSUyRmF2YXRhcnMlMkZqby5wbmciLCJ1cGR" +
                            "hdGVkX2F0IjoiMjAyMC0xMS0wMlQyMDoyMzoxMy4wODBaIiwiZW1haWwiOiJqb2VAZXhhbXBsZS5jb20i" +
                            "LCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiaXNzIjoiaHR0cHM6Ly9kZXYtNi1lcTZkamIuZXUuYXV0aDAuY" +
                            "29tLyIsInN1YiI6ImF1dGgwfDVmNmRlZTJjNTkyNGYwMDA2ZjA3N2RmMCIsImF1ZCI6InpCODVKZm90T1" +
                            "RhYklkU0Fxc0lXUGo2WlY0dENYYUhEIiwiaWF0IjoxNjA0MzQ4NjA2LCJleHAiOjE2MDQzODQ2MDYsIm5" +
                            "vbmNlIjoiM0phR2xRcWtmQlZyeHpEUXVBTmh5M3N6U1VTeE41NEFPbndOUzZobkVTMCJ9.NOSlYr1NB67" +
                            "6qFHecWxNi0gwlKv3DXRo3Vd_KTTuoie9NAl9A0eOYftVId-mJe9kw_ovSSi_aqxUNeKfF_0dHoyP5gRE" +
                            "9wU6RbkH9iuZIi1-gQ5uYjh7ee0mqtld_vhW4aXnNe4zM7v9WgYgWLj9cKReKeDptvMYQP4PKatSySk1J" +
                            "uj_bGPMYQGlYne7vtAxT_xKzy04I3w2jpR0xmTQ2eZRFfdl3iGckS56IWvUi4jPJJkc0OF_UV-I8VVnws" +
                            "cAMNXh0ly_3ZM1m7p-8YHKPuQ4g6k1bT7SJm-D6kPkke__u_ktnDiuTfmPhaGBnr9EDN3fQckHgdg7GgR8J8sF9w"
                    )
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

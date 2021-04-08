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
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType
import strikt.api.expectThat
import strikt.assertions.contains
import strikt.assertions.isEqualTo

internal class OAuth2AuthorizationRequestTest {

    @Test
    fun `deserialization works`() {
        val body = resource("oauth2_authorization_request.json").readText()

        val obj = mapper.readValue(body, OAuth2AuthorizationRequest::class.java)
        expectThat(obj) {
            get(OAuth2AuthorizationRequest::getAuthorizationUri)
                .isEqualTo("https://dev-6-eq6djb.eu.auth0.com/authorize")
            get(OAuth2AuthorizationRequest::getGrantType)
                .isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE)
            get(OAuth2AuthorizationRequest::getResponseType)
                .isEqualTo(OAuth2AuthorizationResponseType.CODE)
            get(OAuth2AuthorizationRequest::getClientId)
                .isEqualTo("zB85JfotOTabIdSAqsIWPj6ZV4tCXaHD")
            get(OAuth2AuthorizationRequest::getRedirectUri)
                .isEqualTo("http://localhost:3000/login/oauth2/code/localhost")
            get(OAuth2AuthorizationRequest::getScopes)
                .contains(
                    "openid", "profile", "offline_access", "name", "given_name", "family_name", "nickname",
                    "email", "email_verified", "picture", "created_at", "identities", "phone", "address"
                )
            get(OAuth2AuthorizationRequest::getState)
                .isEqualTo("uU7JWS6lJJuoFgFS96FCqwusuOLM4bXXoWNxVgJB9kQ=")
            get(OAuth2AuthorizationRequest::getAdditionalParameters)
                .isEqualTo(mapOf("nonce" to "RRUHHEafTSt5AlqphICzybZszLSpG3GC6RW7cyWAscc"))
            get(OAuth2AuthorizationRequest::getAuthorizationRequestUri)
                .isEqualTo(
                    "https://dev-6-eq6djb.eu.auth0.com/authorize?" +
                        "response_type=code&client_id=zB85JfotOTabIdSAqsIWPj6ZV4tCXaHD&" +
                        "scope=openid%20profile%20offline_access%20name%20given_name%20family_name%20nickname%20" +
                        "email%20email_verified%20picture%20created_at%20identities%20phone%20address&" +
                        "state=uU7JWS6lJJuoFgFS96FCqwusuOLM4bXXoWNxVgJB9kQ%3D&" +
                        "redirect_uri=http://localhost:3000/login/oauth2/code/localhost" +
                        "&nonce=RRUHHEafTSt5AlqphICzybZszLSpG3GC6RW7cyWAscc"
                )
            get(OAuth2AuthorizationRequest::getAttributes)
                .isEqualTo(
                    mapOf(
                        "registration_id" to "localhost",
                        "nonce" to "3P_mwTmlV9K2jrdlizc9XYW7rwX8oTZW0DPWM7rIADbHZqb91yR4PNgT6gSyIBhMsoe6T-" +
                            "DPU47KWQ_-MT3rIEMHH6zXutoBfofwB2wSeYUyxxjEgOIx7bmLZAiBFJsD"
                    )
                )
        }
    }

    @Test
    fun `serialization works`() {
        val body = resource("oauth2_authorization_request.json").readText()
        val obj = mapper.readValue(body, OAuth2AuthorizationRequest::class.java)
        assertJsonEquals(
            resource("oauth2_authorization_request.json").readText(),
            mapper.writeValueAsString(obj),
            Configuration.empty().withOptions(Option.IGNORING_ARRAY_ORDER)
        )
    }
}

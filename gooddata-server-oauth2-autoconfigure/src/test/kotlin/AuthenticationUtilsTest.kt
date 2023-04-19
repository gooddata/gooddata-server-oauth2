/*
 * Copyright 2022 GoodData Corporation
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

package com.gooddata.oauth2.server

import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.client.WireMock
import com.github.tomakehurst.wiremock.core.WireMockConfiguration
import org.intellij.lang.annotations.Language
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.http.HttpStatus
import org.springframework.web.client.HttpClientErrorException
import strikt.api.expect
import strikt.api.expectThat
import strikt.assertions.containsExactlyInAnyOrder
import strikt.assertions.endsWith
import strikt.assertions.isEqualTo

internal class AuthenticationUtilsTest {

    lateinit var organization: Organization

    lateinit var properties: HostBasedClientRegistrationRepositoryProperties

    lateinit var clientRegistrationBuilderCache: ClientRegistrationBuilderCache

    @BeforeEach
    internal fun setUp() {
        properties = HostBasedClientRegistrationRepositoryProperties("http://remote", "http://localhost")
        clientRegistrationBuilderCache = CaffeineClientRegistrationCache()
    }

    @Test
    fun buildClientRegistrationDex() {
        organization = Organization(
            id = ORGANIZATION_ID,
            oauthClientId = CLIENT_ID
        )

        val clientRegistration = buildClientRegistration(
            REGISTRATION_ID,
            organization,
            properties,
            clientRegistrationBuilderCache
        )
        expect {
            that(clientRegistration).and {
                get { registrationId }.isEqualTo(REGISTRATION_ID)
                get { clientId }.isEqualTo(CLIENT_ID)
                get { scopes }.containsExactlyInAnyOrder("openid", "profile")
            }
        }
    }

    @Test
    fun buildClientRegistrationIssuerLocationWithCache() {
        organization = Organization(
            id = ORGANIZATION_ID,
            oauthClientId = CLIENT_ID,
            oauthIssuerLocation = mockOidcIssuer()
        )

        val clientRegistrationProvider = {
            buildClientRegistration(
                REGISTRATION_ID,
                organization,
                properties,
                clientRegistrationBuilderCache
            )
        }
        expect {
            that(clientRegistrationProvider()).and {
                get { registrationId }.isEqualTo(REGISTRATION_ID)
                get { clientId }.isEqualTo(CLIENT_ID)
                get { scopes }.containsExactlyInAnyOrder("openid", "profile", "offline_access")
            }
            that(clientRegistrationProvider()).and {
                get { registrationId }.isEqualTo(REGISTRATION_ID)
                get { clientId }.isEqualTo(CLIENT_ID)
            }
        }
    }

    @Test
    fun `build client registration with custom redirect uri`() {
        val customIssuerId = "someCustomIssuerId"
        organization = Organization(
            id = ORGANIZATION_ID,
            oauthClientId = CLIENT_ID,
            oauthIssuerLocation = mockOidcIssuer(),
            oauthIssuerId = customIssuerId,
        )

        expectThat(buildClientRegistration(REGISTRATION_ID, organization, properties, clientRegistrationBuilderCache)) {
            get { registrationId }.isEqualTo(REGISTRATION_ID)
            get { clientId }.isEqualTo(CLIENT_ID)
            get { redirectUri }.endsWith(customIssuerId)
        }
    }

    @Test
    fun `build client registration throws 401 for invalid issuer`() {
        val customIssuerId = "someCustomIssuerId"
        val invalidIssuerLocation = "invalidIssuerLocation"
        organization = Organization(
            id = ORGANIZATION_ID,
            oauthClientId = CLIENT_ID,
            oauthIssuerLocation = invalidIssuerLocation,
            oauthIssuerId = customIssuerId,
        )

        val ex = assertThrows<HttpClientErrorException> {
            buildClientRegistration(REGISTRATION_ID, organization, properties, clientRegistrationBuilderCache)
        }
        assertEquals("401 Authorization failed for given issuer \"$invalidIssuerLocation\"", ex.message)
        assertEquals(HttpStatus.UNAUTHORIZED, ex.statusCode)
    }

    private fun mockOidcIssuer(): String {
        wireMockServer.stubFor(
            WireMock.get(WireMock.urlEqualTo(OIDC_CONFIG_PATH)).willReturn(
                WireMock.okJson(OIDC_CONFIG)
            )
        )
        return wireMockServer.baseUrl()
    }

    companion object {
        private const val ORGANIZATION_ID = "orgId"
        private const val REGISTRATION_ID = "regId"
        private const val CLIENT_ID = "clientId"
        private const val OIDC_CONFIG_PATH = "/.well-known/openid-configuration"

        private val wireMockServer = WireMockServer(WireMockConfiguration().dynamicPort()).apply {
            start()
        }

        @AfterAll
        @JvmStatic
        fun cleanUp() {
            wireMockServer.stop()
        }

        @Language("json")
        private val OIDC_CONFIG = """
            {
              "issuer": "${wireMockServer.baseUrl()}",
              "authorization_endpoint": "${wireMockServer.baseUrl()}/oauth2/v1/authorize",
              "token_endpoint": "${wireMockServer.baseUrl()}/oauth2/v1/token",
              "userinfo_endpoint": "${wireMockServer.baseUrl()}/oauth2/v1/userinfo",
              "registration_endpoint": "${wireMockServer.baseUrl()}/oauth2/v1/clients",
              "jwks_uri": "${wireMockServer.baseUrl()}/oauth2/v1/keys",
              "response_types_supported": [
                "code",
                "id_token",
                "code id_token",
                "code token",
                "id_token token",
                "code id_token token"
              ],
              "response_modes_supported": [
                "query",
                "fragment",
                "form_post",
                "okta_post_message"
              ],
              "grant_types_supported": [
                "authorization_code",
                "implicit",
                "refresh_token",
                "password",
                "urn:ietf:params:oauth:grant-type:device_code"
              ],
              "subject_types_supported": [
                "public"
              ],
              "id_token_signing_alg_values_supported": [
                "RS256"
              ],
              "scopes_supported": [
                "openid",
                "email",
                "profile",
                "address",
                "phone",
                "offline_access",
                "groups"
              ],
              "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
                "client_secret_jwt",
                "private_key_jwt",
                "none"
              ],
              "claims_supported": [
                "iss",
                "ver",
                "sub",
                "aud",
                "iat",
                "exp",
                "jti",
                "auth_time",
                "amr",
                "idp",
                "nonce",
                "name",
                "nickname",
                "preferred_username",
                "given_name",
                "middle_name",
                "family_name",
                "email",
                "email_verified",
                "profile",
                "zoneinfo",
                "locale",
                "address",
                "phone_number",
                "picture",
                "website",
                "gender",
                "birthdate",
                "updated_at",
                "at_hash",
                "c_hash"
              ],
              "code_challenge_methods_supported": [
                "S256"
              ],
              "introspection_endpoint": "${wireMockServer.baseUrl()}/oauth2/v1/introspect",
              "introspection_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
                "client_secret_jwt",
                "private_key_jwt",
                "none"
              ],
              "revocation_endpoint": "${wireMockServer.baseUrl()}/oauth2/v1/revoke",
              "revocation_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
                "client_secret_jwt",
                "private_key_jwt",
                "none"
              ],
              "end_session_endpoint": "${wireMockServer.baseUrl()}/oauth2/v1/logout",
              "request_parameter_supported": true,
              "request_object_signing_alg_values_supported": [
                "HS256",
                "HS384",
                "HS512",
                "RS256",
                "RS384",
                "RS512",
                "ES256",
                "ES384",
                "ES512"
              ],
              "device_authorization_endpoint": "${wireMockServer.baseUrl()}/oauth2/v1/device/authorize"
            }
        """.trimIndent()
    }
}

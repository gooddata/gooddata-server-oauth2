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
import com.gooddata.oauth2.server.OAuthConstants.GD_USER_GROUPS_SCOPE
import com.gooddata.oauth2.server.oauth2.client.fromOidcConfiguration
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import org.intellij.lang.annotations.Language
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import org.springframework.http.HttpStatus
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.web.client.HttpClientErrorException
import org.springframework.web.server.ResponseStatusException
import strikt.api.expect
import strikt.api.expectThat
import strikt.assertions.containsExactlyInAnyOrder
import strikt.assertions.endsWith
import strikt.assertions.isEqualTo
import strikt.assertions.isNotNull
import strikt.assertions.isNull
import java.net.URI
import java.util.stream.Stream

internal class AuthenticationUtilsTest {

    lateinit var organization: Organization

    lateinit var properties: HostBasedClientRegistrationRepositoryProperties

    lateinit var clientRegistrationCache: ClientRegistrationCache

    @BeforeEach
    internal fun setUp() {
        properties = HostBasedClientRegistrationRepositoryProperties("http://remote", "http://localhost")
        clientRegistrationCache = CaffeineClientRegistrationCache()
    }

    @Test
    fun buildClientRegistrationDex() {
        organization = Organization(
            id = ORGANIZATION_ID,
            oauthClientId = CLIENT_ID,
            oauthClientSecret = CLIENT_SECRET
        )

        val clientRegistration = buildClientRegistration(
            REGISTRATION_ID,
            organization,
            properties,
            clientRegistrationCache
        )
        expect {
            that(clientRegistration).and {
                get { registrationId }.isEqualTo(REGISTRATION_ID)
                get { clientId }.isEqualTo(CLIENT_ID)
                get { clientSecret }.isEqualTo(CLIENT_SECRET)
                get { scopes }.containsExactlyInAnyOrder("openid", "profile")
            }
        }
    }

    @ParameterizedTest
    @MethodSource("jitEnabledArguments")
    fun buildClientRegistrationIssuerLocationWithCache(jitEnabled: Boolean, expectedScopes: List<String>) {
        organization = Organization(
            id = ORGANIZATION_ID,
            oauthClientId = CLIENT_ID,
            oauthIssuerLocation = mockOidcIssuer(),
            oauthClientSecret = CLIENT_SECRET,
            jitEnabled = jitEnabled
        )

        val clientRegistrationProvider = {
            buildClientRegistration(
                REGISTRATION_ID,
                organization,
                properties,
                clientRegistrationCache
            )
        }
        expect {
            that(clientRegistrationProvider()).and {
                get { registrationId }.isEqualTo(REGISTRATION_ID)
                get { clientId }.isEqualTo(CLIENT_ID)
                get { scopes }.containsExactlyInAnyOrder(expectedScopes)
            }
            that(clientRegistrationProvider()).and {
                get { registrationId }.isEqualTo(REGISTRATION_ID)
                get { clientId }.isEqualTo(CLIENT_ID)
                get { clientSecret }.isEqualTo(CLIENT_SECRET)
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
            oauthClientSecret = CLIENT_SECRET
        )

        expectThat(buildClientRegistration(REGISTRATION_ID, organization, properties, clientRegistrationCache)) {
            get { registrationId }.isEqualTo(REGISTRATION_ID)
            get { clientId }.isEqualTo(CLIENT_ID)
            get { clientSecret }.isEqualTo(CLIENT_SECRET)
            get { redirectUri }.endsWith(customIssuerId)
        }
    }

    @Test
    fun `should call handleAzureB2CClientRegistration method`() {
        val azureB2CIssuerId = "someAzureB2CIssuerId"
        organization = Organization(
            id = ORGANIZATION_ID,
            oauthClientId = CLIENT_ID,
            oauthIssuerLocation = "https://tenant.b2clogin.com/tenant.onmicrosoft.com/policy/v2.0/",
            oauthIssuerId = azureB2CIssuerId,
            oauthClientSecret = CLIENT_SECRET
        )

        try {
            buildClientRegistration(REGISTRATION_ID, organization, properties, clientRegistrationCache)
        } catch (ex: HttpClientErrorException) {
            // This is expected as the issuer isn't actually available and can be ignored as we just wish to verify
            // that the `handleAzureB2CClientRegistration` method is called when the issuer is an Azure B2C issuer.
            assertEquals(HttpStatus.NOT_FOUND, ex.statusCode)
            assertEquals("404 Not Found: \"The resource you are looking for has been removed, had its name changed, " +
                "or is temporarily unavailable.\"", ex.message)
        }
    }

    @Test
    fun `building fromOidcConfiguration should set values from provided metadata`() {
        val azureB2CIssuerId = "someAzureB2CIssuerId"
        organization = Organization(
            id = ORGANIZATION_ID,
            oauthClientId = CLIENT_ID,
            oauthIssuerLocation = "https://tenant.b2clogin.com/tenant.onmicrosoft.com/policy/v2.0/",
            oauthIssuerId = azureB2CIssuerId,
            oauthClientSecret = CLIENT_SECRET
        )
        val clientRegistrationBuilder = fromOidcConfiguration(VALID_AZURE_B2C_OIDC_CONFIG)
            .clientId(CLIENT_ID)
            .clientSecret(CLIENT_SECRET)

        expect { that(clientRegistrationBuilder) }
        val issuer: String = VALID_AZURE_B2C_OIDC_CONFIG["issuer"].toString()
        val clientRegistration = { clientRegistrationBuilder.buildWithIssuerConfig(organization) }
        expect {
            that(clientRegistration()).and {
                get { registrationId }.isEqualTo(URI.create(issuer).host)
                get { providerDetails.userInfoEndpoint.userNameAttributeName }.isEqualTo("name")
                get { authorizationGrantType }.isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE)
                get { redirectUri }.isEqualTo("{baseUrl}/{action}/oauth2/code/{registrationId}")
                get { providerDetails.authorizationUri }
                    .isEqualTo(VALID_AZURE_B2C_OIDC_CONFIG["authorization_endpoint"] as String?)
                get { providerDetails.configurationMetadata }.isEqualTo(VALID_AZURE_B2C_OIDC_CONFIG)
                get { providerDetails.tokenUri }.isEqualTo(VALID_AZURE_B2C_OIDC_CONFIG["token_endpoint"] as String?)
                get { providerDetails.issuerUri }.isEqualTo(issuer)
                get { clientName }.isEqualTo(issuer)
                get { scopes }.containsExactlyInAnyOrder(AZURE_B2C_SCOPES)
            }
        }
    }

    @ParameterizedTest(name = "build client registration throws 401 for {0}")
    @MethodSource("illegalIssuerArguments")
    fun `build client registration with invalid issuer`(
        case: String,
        issuerLocation: String,
        messageSpecification: String,
    ) {
        val customIssuerId = "someCustomIssuerId"
        organization = Organization(
            id = ORGANIZATION_ID,
            oauthClientId = CLIENT_ID,
            oauthIssuerLocation = issuerLocation,
            oauthIssuerId = customIssuerId,
        )

        val ex = assertThrows<ResponseStatusException> {
            buildClientRegistration(REGISTRATION_ID, organization, properties, clientRegistrationCache)
        }
        assertEquals(
            "401 UNAUTHORIZED \"Authorization failed for given issuer \"$issuerLocation\". $messageSpecification",
            ex.message
        )
        assertEquals(HttpStatus.UNAUTHORIZED, ex.statusCode)
    }

    @Test
    fun `build client registration without mandatory oauth attributes`() {
        val issuer = mockOidcIssuer()
        organization = Organization(
            id = ORGANIZATION_ID,
            oauthClientId = CLIENT_ID,
            oauthIssuerLocation = issuer,
        )

        val ex = assertThrows<ResponseStatusException> {
            buildClientRegistration(REGISTRATION_ID, organization, properties, clientRegistrationCache)
        }
        assertEquals(
            "401 UNAUTHORIZED \"Authorization failed for given issuer $issuer. " +
                "Invalid configuration, missing mandatory attribute client id and/or client secret.\"",
            ex.message
        )
        assertEquals(HttpStatus.UNAUTHORIZED, ex.statusCode)
    }

    @Test
    fun `find user authenticated by UserContextAuthenticationToken`() {
        val token = UserContextAuthenticationToken(Organization(ORGANIZATION_ID), User(USER_ID))

        val result = findAuthenticatedUser(mockk(), ORGANIZATION, token).block()

        expectThat(result) {
            isNotNull().and { get { id }.isEqualTo(USER_ID) }
        }
    }

    @Test
    fun `find user authenticated by JwtAuthenticationToken`() {
        val tokenName = "jwtToken"
        val token: JwtAuthenticationToken = mockk {
            every { name } returns tokenName
        }
        val client: AuthenticationStoreClient = mockk {
            mockUserById(this, ORGANIZATION_ID, tokenName, User(USER_ID))
        }

        val result = findAuthenticatedUser(client, ORGANIZATION, token).block()

        coVerify(exactly = 1) { client.getUserById(any(), any()) }
        expectThat(result) {
            isNotNull().and { get { id }.isEqualTo(USER_ID) }
        }
    }

    @Test
    fun `find user authenticated by OAuth2AuthenticationToken`() {
        val subClaim = "sub"
        val token: OAuth2AuthenticationToken = mockk {
            every { principal.attributes[IdTokenClaimNames.SUB] } returns subClaim
        }
        val client: AuthenticationStoreClient = mockk {
            mockUserByAuthId(this, ORGANIZATION_ID, subClaim, User(USER_ID))
        }

        val result = findAuthenticatedUser(client, ORGANIZATION, token).block()

        coVerify(exactly = 1) { client.getUserByAuthenticationId(any(), any()) }
        expectThat(result) {
            isNotNull().and { get { id }.isEqualTo(USER_ID) }
        }
    }

    @Test
    fun `find user authenticated by not specified token`() {
        val token: Authentication = mockk()

        val result = findAuthenticatedUser(mockk(), ORGANIZATION, token).block()

        expectThat(result).isNull()
    }

    @Test
    fun `user not found by OAuth2AuthenticationToken`() {
        val subClaim = "sub"
        val token: OAuth2AuthenticationToken = mockk {
            every { principal.attributes[IdTokenClaimNames.SUB] } returns subClaim
        }
        val client: AuthenticationStoreClient = mockk {
            mockUserByAuthId(this, ORGANIZATION_ID, subClaim, null)
        }

        val result = findAuthenticatedUser(client, ORGANIZATION, token).block()

        coVerify(exactly = 1) { client.getUserByAuthenticationId(any(), any()) }
        expectThat(result).isNull()
    }

    @ParameterizedTest
    @MethodSource("userGroups")
    fun `should parse user groups from token`(userGroups: Any) {
        val token: OAuth2AuthenticationToken = mockk {
            every { principal.attributes[GD_USER_GROUPS_SCOPE] } returns userGroups
        }

        val result = token.getClaimList(GD_USER_GROUPS_SCOPE)

        expectThat(result).isEqualTo(listOf("group1", "group2"))
    }

    @Test
    fun `validateAzureB2CMetadata returns true for valid metadata`() {
        val uri = URI.create(AZURE_B2C_ISSUER)
        assertTrue(validateAzureB2CMetadata(VALID_AZURE_B2C_OIDC_CONFIG, uri).isValid)
    }

    @Test
    fun `validateAzureB2CMetadata returns false for invalid metadata`() {
        val uri = URI.create(AZURE_B2C_ISSUER)
        val validationResult = validateAzureB2CMetadata(INVALID_AZURE_B2C_OIDC_CONFIG, uri)
        assertFalse(validationResult.isValid)
        // The [INVALID_AZURE_B2C_OIDC_CONFIG] has 5 mismatched endpoints
        assertEquals(5, validationResult.mismatchedEndpoints.size)
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
        private const val CLIENT_SECRET = "secret"
        private const val OIDC_CONFIG_PATH = "/.well-known/openid-configuration"
        private const val USER_ID = "userId"
        private const val AZURE_B2C_ISSUER = "https://tenant.b2clogin.com/tenant.onmicrosoft.com/policy/v2.0"
        private val AZURE_B2C_SCOPES = listOf("openid", "profile", "offline_access", CLIENT_ID)
        private val UNVERSIONED_AZURE_B2C_ISSUER = AZURE_B2C_ISSUER.removeVersionSegment()
        private val ORGANIZATION = Organization(ORGANIZATION_ID)
        private val wireMockServer = WireMockServer(WireMockConfiguration().dynamicPort()).apply {
            start()
        }

        @AfterAll
        @JvmStatic
        fun cleanUp() {
            wireMockServer.stop()
        }

        @JvmStatic
        fun userGroups() = Stream.of(
            Arguments.of("group1,group2"),
            Arguments.of(listOf("group1", "group2"))
        )

        @JvmStatic
        fun illegalIssuerArguments() = Stream.of(
            Arguments.of(
                "non matching issuer",
                "https://gooddata-stg.us.auth0.com/wrong",
                "The Issuer \"https://gooddata-stg.us.auth0.com/\" provided in the configuration metadata " +
                    "did not match the requested issuer \"https://gooddata-stg.us.auth0.com/wrong\"\""
            ),
            Arguments.of(
                "invalid issuer",
                "https://www.share.bfqa.org/",
                "Unable to resolve Configuration with the provided Issuer of \"https://www.share.bfqa.org/\"\""
            )
        )

        @JvmStatic
        fun jitEnabledArguments() = Stream.of(
            Arguments.of(true, listOf("openid", "profile", "email", "offline_access", GD_USER_GROUPS_SCOPE)),
            Arguments.of(false, listOf("openid", "profile", "offline_access"))
        )

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

        private val VALID_AZURE_B2C_OIDC_CONFIG: Map<String, Any> = mapOf(
            "issuer" to "https://some-microsoft-issuer.com/someGuid/v2.0/",
            "authorization_endpoint" to "${UNVERSIONED_AZURE_B2C_ISSUER}/oauth2/v1/authorize",
            "token_endpoint" to "${UNVERSIONED_AZURE_B2C_ISSUER}/oauth2/v1/token",
            "userinfo_endpoint" to "${UNVERSIONED_AZURE_B2C_ISSUER}/oauth2/v1/userinfo",
            "registration_endpoint" to "${UNVERSIONED_AZURE_B2C_ISSUER}/oauth2/v1/clients",
            "jwks_uri" to "${UNVERSIONED_AZURE_B2C_ISSUER}/oauth2/v1/keys",
            "response_types_supported" to listOf(
                "code",
                "id_token",
                "code id_token",
                "code token",
                "id_token token",
                "code id_token token"
            ),
            "response_modes_supported" to listOf(
                "query",
                "fragment",
                "form_post",
                "okta_post_message"
            ),
            "grant_types_supported" to listOf(
                "authorization_code",
                "implicit",
                "refresh_token",
                "password",
                "urn:ietf:params:oauth:grant-type:device_code"
            ),
            "subject_types_supported" to listOf("public"),
            "id_token_signing_alg_values_supported" to listOf("RS256"),
            "scopes_supported" to listOf(
                "openid",
                "email",
                "profile",
                "address",
                "phone",
                "offline_access",
                "groups"
            ),
            "token_endpoint_auth_methods_supported" to listOf(
                "client_secret_basic",
                "client_secret_post",
                "client_secret_jwt",
                "private_key_jwt",
                "none"
            ),
            "claims_supported" to listOf(
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
            ),
            "code_challenge_methods_supported" to listOf("S256"),
            "introspection_endpoint" to "${UNVERSIONED_AZURE_B2C_ISSUER}/oauth2/v1/introspect",
            "introspection_endpoint_auth_methods_supported" to listOf(
                "client_secret_basic",
                "client_secret_post",
                "client_secret_jwt",
                "private_key_jwt",
                "none"
            ),
            "revocation_endpoint" to "${UNVERSIONED_AZURE_B2C_ISSUER}/oauth2/v1/revoke",
            "revocation_endpoint_auth_methods_supported" to listOf(
                "client_secret_basic",
                "client_secret_post",
                "client_secret_jwt",
                "private_key_jwt",
                "none"
            ),
            "end_session_endpoint" to "${UNVERSIONED_AZURE_B2C_ISSUER}/oauth2/v1/logout",
            "request_parameter_supported" to true,
            "request_uri_parameter_supported" to true,
            "request_object_signing_alg_values_supported" to listOf(
                "HS256",
                "HS384",
                "HS512",
                "RS256",
                "RS384",
                "RS512",
                "ES256",
                "ES384",
                "ES512"
            ),
            "device_authorization_endpoint" to "${UNVERSIONED_AZURE_B2C_ISSUER}/oauth2/v1/device/authorize"
        )

        private val INVALID_AZURE_B2C_OIDC_CONFIG: Map<String, Any> = mapOf(
            "issuer" to "https://some-microsoft-issuer.com/someGuid/v2.0/",
            "authorization_endpoint" to "https://invalid-issuer/oauth2/v1/authorize",
            "token_endpoint" to "https://invalid-issuer/oauth2/v1/token",
            "userinfo_endpoint" to "https://invalid-issuer/oauth2/v1/userinfo",
            "registration_endpoint" to "https://invalid-issuer/oauth2/v1/clients",
            "jwks_uri" to "https://invalid-issuer/oauth2/v1/keys",
            "response_types_supported" to listOf(
                "code",
                "id_token",
                "code id_token",
                "code token",
                "id_token token",
                "code id_token token"
            ),
            "response_modes_supported" to listOf(
                "query",
                "fragment",
                "form_post",
                "okta_post_message"
            ),
            "grant_types_supported" to listOf(
                "authorization_code",
                "implicit",
                "refresh_token",
                "password",
                "urn:ietf:params:oauth:grant-type:device_code"
            ),
            "subject_types_supported" to listOf("public"),
            "id_token_signing_alg_values_supported" to listOf("RS256"),
            "scopes_supported" to listOf(
                "openid",
                "email",
                "profile",
                "address",
                "phone",
                "offline_access",
                "groups"
            ),
            "token_endpoint_auth_methods_supported" to listOf(
                "client_secret_basic",
                "client_secret_post",
                "client_secret_jwt",
                "private_key_jwt",
                "none"
            ),
            "claims_supported" to listOf(
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
            ),
            "code_challenge_methods_supported" to listOf("S256"),
            "introspection_endpoint" to "https://invalid-issuer/oauth2/v1/introspect",
            "introspection_endpoint_auth_methods_supported" to listOf(
                "client_secret_basic",
                "client_secret_post",
                "client_secret_jwt",
                "private_key_jwt",
                "none"
            ),
            "revocation_endpoint" to "https://invalid-issuer/oauth2/v1/revoke",
            "revocation_endpoint_auth_methods_supported" to listOf(
                "client_secret_basic",
                "client_secret_post",
                "client_secret_jwt",
                "private_key_jwt",
                "none"
            ),
            "end_session_endpoint" to "https://invalid-issuer/oauth2/v1/logout",
            "request_parameter_supported" to true,
            "request_uri_parameter_supported" to true,
            "request_object_signing_alg_values_supported" to listOf(
                "HS256",
                "HS384",
                "HS512",
                "RS256",
                "RS384",
                "RS512",
                "ES256",
                "ES384",
                "ES512"
            ),
            "device_authorization_endpoint" to "https://invalid-issuer/oauth2/v1/device/authorize"
        )
    }
}

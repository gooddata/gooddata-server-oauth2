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
package com.gooddata.oauth2.server

import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.client.WireMock.aResponse
import com.github.tomakehurst.wiremock.client.WireMock.get
import com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo
import com.github.tomakehurst.wiremock.core.WireMockConfiguration
import com.gooddata.oauth2.server.CookieServerSecurityContextRepository.Companion.OAUTH_TOKEN_CACHE_KEY
import com.google.crypto.tink.CleartextKeysetHandle
import com.google.crypto.tink.JsonKeysetReader
import com.nimbusds.openid.connect.sdk.claims.UserInfo
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.spyk
import io.mockk.verify
import io.netty.handler.codec.http.cookie.CookieHeaderNames
import net.javacrumbs.jsonunit.JsonAssert.assertJsonEquals
import net.javacrumbs.jsonunit.core.Configuration
import net.javacrumbs.jsonunit.core.Option
import net.javacrumbs.jsonunit.core.util.ResourceUtils.resource
import org.intellij.lang.annotations.Language
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.springframework.http.HttpCookie
import org.springframework.http.server.RequestPath
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.core.AuthenticationMethod
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority
import org.springframework.security.oauth2.jwt.JoseHeaderNames
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtException
import org.springframework.util.CollectionUtils.toMultiValueMap
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import reactor.test.StepVerifier
import strikt.api.expectThat
import strikt.api.expectThrows
import strikt.assertions.containsKey
import strikt.assertions.isA
import strikt.assertions.isEqualTo
import strikt.assertions.isNotNull
import strikt.assertions.isTrue
import java.net.URI
import java.time.Duration
import java.time.Instant
import java.util.*

internal class CookieServerSecurityContextRepositoryTest {

    private val clientRegistrationRepository: ReactiveClientRegistrationRepository = mockk()

    private val properties = CookieServiceProperties(
        Duration.ofDays(1),
        CookieHeaderNames.SameSite.Lax,
        Duration.ofDays(1)
    )

    @Language("JSON")
    private val keyset = """
        {
            "primaryKeyId": 482808123,
            "key": [
                {
                    "keyData": {
                        "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
                        "keyMaterialType": "SYMMETRIC",
                        "value": "GiBpR+IuA4xWtq5ZijTXae/Y9plMy0TMMc97wqdOrK7ndA=="
                    },
                    "outputPrefixType": "TINK",
                    "keyId": 482808123,
                    "status": "ENABLED"
                }
            ]
        }
    """

    private val client: AuthenticationStoreClient = mockk {
        mockOrganization(this, LOCALHOST, Organization(ORG_ID))
        mockCookieSecurityProperties(
            this,
            ORG_ID,
            CookieSecurityProperties(
                keySet = CleartextKeysetHandle.read(JsonKeysetReader.withBytes(keyset.toByteArray())),
                lastRotation = Instant.now(),
                rotationInterval = Duration.ofDays(1),
            )
        )
    }

    private val cookieSerializer = CookieSerializer(properties, client)

    private val cookieService = spyk(ReactiveCookieService(properties, cookieSerializer))

    private val exchange: ServerWebExchange = mockk(relaxed = true) {
        every { request.uri.host } returns LOCALHOST
        every { request.uri.scheme } returns "https"
        // every { request.uri } returns URI(LOCALHOST)
        every { request.path } returns RequestPath.parse("/some/path", "/some")
    }

    private val jwkCache = CaffeineJwkCache()

    private val jwtDecoderFactory = spyk(JwkCachingReactiveDecoderFactory(jwkCache))

    private val authorizedClientRepository: ServerOAuth2AuthorizedClientRepository = mockk()

    private val repositoryAwareOidcTokensRefreshingService: RepositoryAwareOidcTokensRefreshingService = mockk()

    private val repository = CookieServerSecurityContextRepository(
        clientRegistrationRepository,
        cookieService,
        jwtDecoderFactory,
        repositoryAwareOidcTokensRefreshingService,
        authorizedClientRepository,
    )

    @AfterEach
    internal fun tearDown() {
        wireMockServer.resetAll()
    }

    @Test
    fun `should save context`() {
        val idToken = OidcIdToken(
            "tokenValue",
            Instant.EPOCH,
            Instant.EPOCH.plusSeconds(1),
            mapOf(IdTokenClaimNames.SUB to "sub claim")
        )
        val oidcUser = DefaultOidcUser(
            listOf(OidcUserAuthority(idToken)),
            idToken
        )
        val context = SecurityContextImpl(
            OAuth2AuthenticationToken(
                oidcUser,
                emptyList(),
                "registrationId"
            )
        )

        val slot = slot<String>()
        every { cookieService.createCookie(any(), any(), capture(slot)) } returns Mono.empty()

        StepVerifier.create(repository.save(exchange, context))
            .verifyComplete()

        verify(exactly = 1) { cookieService.createCookie(exchange, SPRING_SEC_SECURITY_CONTEXT, any()) }

        assertJsonEquals(
            resource("mock_authentication_token.json").readText(),
            slot.captured,
            Configuration.empty().withOptions(Option.IGNORING_ARRAY_ORDER)
        )
    }

    @Test
    fun `should remove context from cookies`() {
        every { cookieService.invalidateCookie(any(), any()) } returns Unit

        val response = repository.save(exchange, null)
        expectThat(response.blockOptional()) {
            get(Optional<Void>::isEmpty).isTrue()
        }

        verify(exactly = 1) { cookieService.invalidateCookie(exchange, SPRING_SEC_SECURITY_CONTEXT) }
    }

    @Test
    fun `should not load context when nothing is stored in cookies`() {
        every { exchange.attributes } returns emptyMap()
        every { exchange.request.uri } returns URI.create("http://localhost")
        every { exchange.request.cookies } returns toMultiValueMap(emptyMap())

        val context = repository.load(exchange)

        expectThat(context.blockOptional()) {
            get(Optional<SecurityContext>::isEmpty).isTrue()
        }
    }

    @Test
    fun `should not load context when nonsense is stored in cookies`() {
        every { exchange.attributes } returns provideAttributesMap()
        every { exchange.request.uri } returns URI.create("http://localhost")
        every { exchange.request.cookies } returns toMultiValueMap(
            mapOf(SPRING_SEC_SECURITY_CONTEXT to listOf(HttpCookie(SPRING_SEC_SECURITY_CONTEXT, "something")))
        )

        val context = repository.load(exchange)

        expectThat(context.blockOptional()) {
            get(Optional<SecurityContext>::isEmpty).isTrue()
        }
    }

    @Test
    fun `should not load context from cookie if registration id is not mapped`() {
        every { exchange.attributes } returns provideAttributesMap()
        every { exchange.request.uri } returns URI.create("http://localhost")
        mockSecurityContextCookie(resource("oauth2_authentication_token.json").readText())
        every { clientRegistrationRepository.findByRegistrationId(any()) } returns Mono.empty()

        val context = repository.load(exchange)

        expectThat(context.blockOptional()) {
            get(Optional<SecurityContext>::isEmpty).isTrue()
        }
    }

    @Test
    fun `should load context from cookie`() {
        val attributesMap = provideAttributesMap()
        every { exchange.attributes } returns attributesMap
        every { exchange.request.uri } returns URI.create("http://localhost")
        mockSecurityContextCookie(resource("oauth2_authentication_token_long.json").readText())
        every { clientRegistrationRepository.findByRegistrationId(any()) } returns Mono.just(
            ClientRegistration
                .withRegistrationId(LOCALHOST)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .authorizationUri("http://localhost:${wireMockServer.port()}/dex/auth")
                .tokenUri("http://localhost:${wireMockServer.port()}/dex/token")
                .userInfoUri("http://localhost:${wireMockServer.port()}/dex/userinfo")
                .userInfoAuthenticationMethod(AuthenticationMethod("header"))
                .jwkSetUri("http://localhost:${wireMockServer.port()}/dex/keys")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .scope("openid", "profile")
                .userNameAttributeName("name")
                .clientId("zB85JfotOTabIdSAqsIWPj6ZV4tCXaHD")
                .build()
        )
        wireMockServer
            .stubFor(
                get(urlEqualTo("/dex/keys"))
                    .willReturn(aResponse().withBody(resource("keySet.json").readText()))
            )

        val context = repository.load(exchange).blockOptional().get()

        expectThat(context.authentication) {
            isA<OAuth2AuthenticationToken>()
                .get(OAuth2AuthenticationToken::getAuthorizedClientRegistrationId)
                .isEqualTo(LOCALHOST)
        }
        expectThat(attributesMap).containsKey(OAUTH_TOKEN_CACHE_KEY)
    }

    @Test
    fun `should load context from token cache`() {
        val token = mockk<OAuth2AuthenticationToken>()
        every { exchange.attributes[OAUTH_TOKEN_CACHE_KEY] } returns token

        val context = repository.load(exchange).blockOptional().get()

        expectThat(context.authentication).isEqualTo(token)
    }

    @Test
    fun `should load context with refreshed token after its expiration`() {
        val attributesMap = provideAttributesMap()
        every { exchange.attributes } returns attributesMap
        every { exchange.request.uri } returns URI.create("http://localhost")
        mockSecurityContextCookie(resource("oauth2_authentication_token.json").readText())
        every { cookieService.createCookie(any(), any(), any()) } returns Mono.empty()
        every { clientRegistrationRepository.findByRegistrationId(any()) } returns Mono.just(mockk {
            every { registrationId } returns "123"
            every { providerDetails.userInfoEndpoint.userNameAttributeName } returns "sub"
        })
        every { jwtDecoderFactory.createDecoder(any()) } returns mockk {
            // wrap the expired exception to check if it's properly sanitized
            every { decode("tokenValue") } returns Mono.error(JwtException("error", InternalJwtExpiredException()))
            every { decode("newTokenValue") } returns Mono.just(
                Jwt(
                    "tokenValue",
                    Instant.parse("2023-02-18T10:15:30.00Z"),
                    Instant.parse("2023-02-28T10:15:30.00Z"),
                    mapOf(
                        JoseHeaderNames.ALG to "RS256"
                    ),
                    mapOf(
                        UserInfo.NAME_CLAIM_NAME to "userName",
                        IdTokenClaimNames.SUB to "newTokenUserSub",
                        IdTokenClaimNames.IAT to Instant.EPOCH,
                    ),
                )
            )
        }
        every {
            repositoryAwareOidcTokensRefreshingService.refreshTokensIfPossible(any(), any(), any())
        } returns Mono.just(mockk {
            every { additionalParameters } returns mapOf(OidcParameterNames.ID_TOKEN to "newTokenValue")
        })

        val context = repository.load(exchange).block()

        // check if new cookie is set
        verify { cookieService.createCookie(exchange, SPRING_SEC_SECURITY_CONTEXT, any()) }

        expectThat(context).isNotNull().get { authentication }
            .isA<OAuth2AuthenticationToken>()
            .get { principal.name }.isEqualTo("newTokenUserSub")
        expectThat(attributesMap).containsKey(OAUTH_TOKEN_CACHE_KEY)
    }

    @Test
    fun `should invalidate cookies when token refresh returns empty response`() {
        every { exchange.attributes } returns provideAttributesMap()
        every { exchange.request.uri } returns URI.create("http://localhost")
        mockSecurityContextCookie(resource("oauth2_authentication_token.json").readText())
        every { clientRegistrationRepository.findByRegistrationId(any()) } returns Mono.just(mockk())
        every { jwtDecoderFactory.createDecoder(any()) } returns mockk {
            every { decode("tokenValue") } returns Mono.error(JwtException("error", InternalJwtExpiredException()))
        }
        every {
            repositoryAwareOidcTokensRefreshingService.refreshTokensIfPossible(any(), any(), any())
        } returns Mono.empty()
        every { authorizedClientRepository.removeAuthorizedClient(any(), any(), any()) } returns Mono.empty()
        every { cookieService.invalidateCookie(any(), any()) } returns Unit

        expectThrows<CookieDecodeException> {
            repository.load(exchange).block()
        }

        // check if new cookie is not set
        verify(exactly = 0) { cookieService.createCookie(exchange, SPRING_SEC_SECURITY_CONTEXT, any()) }
        verify {
            authorizedClientRepository.removeAuthorizedClient(any(), any(), any())
            cookieService.invalidateCookie(exchange, SPRING_SEC_SECURITY_CONTEXT)
        }
    }

    @Test
    fun `should invalidate cookies when token refresh does not contain ID token`() {
        every { exchange.attributes } returns provideAttributesMap()
        every { exchange.request.uri } returns URI.create("http://localhost")
        mockSecurityContextCookie(resource("oauth2_authentication_token.json").readText())
        every { clientRegistrationRepository.findByRegistrationId(any()) } returns Mono.just(mockk())
        every { jwtDecoderFactory.createDecoder(any()) } returns mockk {
            every { decode("tokenValue") } returns Mono.error(JwtException("error", InternalJwtExpiredException()))
        }
        every {
            repositoryAwareOidcTokensRefreshingService.refreshTokensIfPossible(any(), any(), any())
        } returns Mono.just(mockk(relaxed = true))
        every { authorizedClientRepository.removeAuthorizedClient(any(), any(), any()) } returns Mono.empty()
        every { cookieService.invalidateCookie(any(), any()) } returns Unit

        expectThrows<CookieDecodeException> {
            repository.load(exchange).block()
        }

        // check if new cookie is not set
        verify(exactly = 0) { cookieService.createCookie(exchange, SPRING_SEC_SECURITY_CONTEXT, any()) }
        verify {
            authorizedClientRepository.removeAuthorizedClient(any(), any(), any())
            cookieService.invalidateCookie(exchange, SPRING_SEC_SECURITY_CONTEXT)
        }
    }

    @Test
    fun `should invalidate cookies when common error occurred during token decoding`() {
        every { exchange.attributes } returns provideAttributesMap()
        every { exchange.request.uri } returns URI.create("http://localhost")
        mockSecurityContextCookie(resource("oauth2_authentication_token.json").readText())
        every { clientRegistrationRepository.findByRegistrationId(any()) } returns Mono.just(mockk())
        every { jwtDecoderFactory.createDecoder(any()) } returns mockk {
            every { decode("tokenValue") } returns Mono.error(JwtException("non-expired error"))
        }
        every { authorizedClientRepository.removeAuthorizedClient(any(), any(), any()) } returns Mono.empty()
        every { cookieService.invalidateCookie(any(), any()) } returns Unit

        expectThrows<CookieDecodeException> {
            repository.load(exchange).block()
        }

        // check if new cookie is not set
        verify(exactly = 0) { cookieService.createCookie(exchange, SPRING_SEC_SECURITY_CONTEXT, any()) }
        verify {
            authorizedClientRepository.removeAuthorizedClient(any(), any(), any())
            cookieService.invalidateCookie(exchange, SPRING_SEC_SECURITY_CONTEXT)
        }
    }

    private fun mockSecurityContextCookie(tokenJson: String) {
        every { exchange.request.cookies } returns toMultiValueMap(
            mapOf(
                SPRING_SEC_SECURITY_CONTEXT to listOf(
                    HttpCookie(
                        SPRING_SEC_SECURITY_CONTEXT, cookieSerializer.encodeCookieBlocking(
                            exchange,
                            tokenJson
                        )
                    )
                )
            )
        )
    }

    private fun provideAttributesMap() = mutableMapOf<String, Any>(
        OrganizationWebFilter.ORGANIZATION_CACHE_KEY to Organization(ORG_ID)
    )

    companion object {
        private const val ORG_ID = "org"
        private const val LOCALHOST = "localhost"
        private val wireMockServer = WireMockServer(WireMockConfiguration().dynamicPort()).apply {
            start()
        }

        @AfterAll
        @JvmStatic
        fun cleanUp() {
            wireMockServer.stop()
        }
    }
}

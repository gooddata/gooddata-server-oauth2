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
import com.google.crypto.tink.CleartextKeysetHandle
import com.google.crypto.tink.JsonKeysetReader
import io.mockk.coEvery
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
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.oauth2.core.AuthenticationMethod
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority
import org.springframework.util.CollectionUtils.toMultiValueMap
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import strikt.api.expectThat
import strikt.assertions.isA
import strikt.assertions.isEqualTo
import strikt.assertions.isTrue
import java.net.URI
import java.time.Duration
import java.time.Instant
import java.util.Optional

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
        coEvery { getOrganizationByHostname("localhost") } returns Organization("org")
        coEvery { getCookieSecurityProperties("org") } returns CookieSecurityProperties(
            keySet = CleartextKeysetHandle.read(JsonKeysetReader.withBytes(keyset.toByteArray())),
            lastRotation = Instant.now(),
            rotationInterval = Duration.ofDays(1),
        )
    }

    private val cookieSerializer = CookieSerializer(properties, client)

    private val cookieService = spyk(ReactiveCookieService(properties, cookieSerializer))

    private val exchange: ServerWebExchange = mockk()

    private val jwkCache = CaffeineJwkCache()

    private val jwtDecoderFactory = JwkCachingReactiveDecoderFactory(jwkCache)

    private val repository = CookieServerSecurityContextRepository(
        clientRegistrationRepository,
        cookieService,
        jwtDecoderFactory
    )

    @AfterEach
    internal fun tearDown() {
        wireMockServer.resetAll()
    }

    @Test
    fun `should save context`() {
        val idToken = OidcIdToken(
            "tokenValue", Instant.EPOCH, Instant.EPOCH.plusSeconds(1), mapOf(IdTokenClaimNames.SUB to null)
        )
        val context = SecurityContextImpl(
            OAuth2AuthenticationToken(
                DefaultOidcUser(
                    listOf(OidcUserAuthority(idToken)),
                    idToken
                ),
                emptyList(),
                "registrationId"
            )
        )
        val slot = slot<String>()
        every { cookieService.createCookie(any(), any(), capture(slot)) } returns Unit

        val response = repository.save(exchange, context)
        expectThat(response.blockOptional()) {
            get(Optional<Void>::isEmpty).isTrue()
        }

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
        every { exchange.request.uri } returns URI.create("http://localhost")
        every { exchange.request.cookies } returns toMultiValueMap(emptyMap())

        val context = repository.load(exchange)

        expectThat(context.blockOptional()) {
            get(Optional<SecurityContext>::isEmpty).isTrue()
        }
    }

    @Test
    fun `should not load context when nonsense is stored in cookies`() {
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
        val body = resource("oauth2_authentication_token.json").readText()
        every { exchange.request.uri } returns URI.create("http://localhost")
        every { exchange.request.cookies } returns toMultiValueMap(
            mapOf(
                SPRING_SEC_SECURITY_CONTEXT to listOf(
                    HttpCookie(SPRING_SEC_SECURITY_CONTEXT, cookieSerializer.encodeCookie("localhost", body))
                )
            )
        )
        every { clientRegistrationRepository.findByRegistrationId(any()) } returns Mono.empty()

        val context = repository.load(exchange)

        expectThat(context.blockOptional()) {
            get(Optional<SecurityContext>::isEmpty).isTrue()
        }
    }

    @Test
    fun `should load context from cookie`() {
        val body = resource("oauth2_authentication_token_long.json").readText()
        every { exchange.request.uri } returns URI.create("http://localhost")
        every { exchange.request.cookies } returns toMultiValueMap(
            mapOf(
                SPRING_SEC_SECURITY_CONTEXT to listOf(
                    HttpCookie(SPRING_SEC_SECURITY_CONTEXT, cookieSerializer.encodeCookie("localhost", body))
                )
            )
        )
        every { clientRegistrationRepository.findByRegistrationId(any()) } returns Mono.just(
            ClientRegistration
                .withRegistrationId("localhost")
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
                .isEqualTo("localhost")
        }
    }

    companion object {
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

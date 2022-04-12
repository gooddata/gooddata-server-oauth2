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
package com.gooddata.oauth2.server.reactive

import com.gooddata.oauth2.server.common.AuthenticationStoreClient
import com.gooddata.oauth2.server.common.CookieSecurityProperties
import com.gooddata.oauth2.server.common.CookieSerializer
import com.gooddata.oauth2.server.common.Organization
import com.gooddata.oauth2.server.common.SPRING_SEC_OAUTH2_AUTHZ_CLIENT
import com.gooddata.oauth2.server.common.SPRING_SEC_SECURITY_CONTEXT
import com.gooddata.oauth2.server.common.User
import com.google.crypto.tink.CleartextKeysetHandle
import com.google.crypto.tink.JsonKeysetReader
import com.ninjasquad.springmockk.MockkBean
import io.mockk.coEvery
import io.mockk.every
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.reactor.ReactorContext
import kotlinx.coroutines.reactor.asCoroutineContext
import net.javacrumbs.jsonunit.core.util.ResourceUtils
import org.intellij.lang.annotations.Language
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Import
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException
import org.springframework.security.web.server.context.ServerSecurityContextRepository
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.test.web.reactive.server.expectBody
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.server.ResponseStatusException
import reactor.core.publisher.Mono
import reactor.util.context.Context
import reactor.util.context.ContextView
import java.time.Duration
import java.time.Instant
import kotlin.coroutines.coroutineContext

@WebFluxTest(properties = ["spring.security.oauth2.client.applogin.allow-redirect=https://localhost:8443"])
@Import(ServerOAuth2AutoConfiguration::class, UserContextWebFluxTest.Config::class)
class UserContextWebFluxTest(
    @Autowired private val webClient: WebTestClient,
    @Autowired private val serverSecurityContextRepository: ServerSecurityContextRepository,
    @Autowired private val authenticationStoreClient: AuthenticationStoreClient,
    @Autowired private val cookieSerializer: CookieSerializer,
) {
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

    @Test
    fun `filter works with cookies`() {
        everyValidSecurityContext()
        everyValidOrganization()
        coEvery { authenticationStoreClient.getUserByAuthenticationId("organizationTestId", "sub") } returns User(
            "userTestId",
        )
        coEvery { authenticationStoreClient.getCookieSecurityProperties("organizationTestId") } returns
            CookieSecurityProperties(
                keySet = CleartextKeysetHandle.read(JsonKeysetReader.withBytes(keyset.toByteArray())),
                lastRotation = Instant.now(),
                rotationInterval = Duration.ofDays(1),
            )
        val authenticationToken = ResourceUtils.resource("oauth2_authentication_token.json").readText()
        val authorizedClient = ResourceUtils.resource("simplified_oauth2_authorized_client.json").readText()

        webClient.get().uri("http://localhost/")
            .cookie(SPRING_SEC_SECURITY_CONTEXT, cookieSerializer.encodeCookie("localhost", authenticationToken))
            .cookie(SPRING_SEC_OAUTH2_AUTHZ_CLIENT, cookieSerializer.encodeCookie("localhost", authorizedClient))
            .exchange()
            .expectStatus()
            .isOk
            .expectBody<String>()
            .isEqualTo("sub <userTestId@organizationTestId>")
    }

    @Test
    fun `redirects appLogin with cookies`() {
        everyValidSecurityContext()
        everyValidOrganization()
        coEvery { authenticationStoreClient.getUserByAuthenticationId("organizationTestId", "sub") } returns User(
            "userTestId",
        )
        coEvery { authenticationStoreClient.getCookieSecurityProperties("organizationTestId") } returns
            CookieSecurityProperties(
                keySet = CleartextKeysetHandle.read(JsonKeysetReader.withBytes(keyset.toByteArray())),
                lastRotation = Instant.now(),
                rotationInterval = Duration.ofDays(1),
            )
        val authenticationToken = ResourceUtils.resource("oauth2_authentication_token.json").readText()
        val authorizedClient = ResourceUtils.resource("simplified_oauth2_authorized_client.json").readText()

        webClient.get().uri("http://localhost/appLogin?redirectTo=/api/profile")
            .cookie(SPRING_SEC_SECURITY_CONTEXT, cookieSerializer.encodeCookie("localhost", authenticationToken))
            .cookie(SPRING_SEC_OAUTH2_AUTHZ_CLIENT, cookieSerializer.encodeCookie("localhost", authorizedClient))
            .exchange()
            .expectStatus()
            .isFound
            .expectHeader().location("/api/profile")
    }

    @Test
    fun `redirects appLogin with absolute uri with cookies`() {
        everyValidSecurityContext()
        everyValidOrganization()
        coEvery { authenticationStoreClient.getUserByAuthenticationId("organizationTestId", "sub") } returns User(
            "userId",
        )
        coEvery { authenticationStoreClient.getCookieSecurityProperties("organizationTestId") } returns
            CookieSecurityProperties(
                keySet = CleartextKeysetHandle.read(JsonKeysetReader.withBytes(keyset.toByteArray())),
                lastRotation = Instant.now(),
                rotationInterval = Duration.ofDays(1),
            )
        coEvery { authenticationStoreClient.getOrganizationByHostname("localhost") } returns Organization(
            id = "organizationTestId",
            allowedOrigins = listOf("https://localhost:8443")
        )
        val authenticationToken = ResourceUtils.resource("oauth2_authentication_token.json").readText()
        val authorizedClient = ResourceUtils.resource("simplified_oauth2_authorized_client.json").readText()

        webClient.get().uri("http://localhost/appLogin?redirectTo=https://localhost:8443/api/profile")
            .cookie(SPRING_SEC_SECURITY_CONTEXT, cookieSerializer.encodeCookie("localhost", authenticationToken))
            .cookie(SPRING_SEC_OAUTH2_AUTHZ_CLIENT, cookieSerializer.encodeCookie("localhost", authorizedClient))
            .exchange()
            .expectStatus()
            .isFound
            .expectHeader().location("https://localhost:8443/api/profile")
    }

    @Test
    fun `filter redirects without cookies`() {
        every { serverSecurityContextRepository.load(any()) } returns Mono.empty()

        webClient.get().uri("http://localhost/")
            .exchange()
            .expectStatus()
            .isFound
            .expectHeader().location("/oauth2/authorization/localhost")
            .expectCookie().exists("SPRING_REDIRECT_URI")
    }

    @Test
    fun `filter redirects appLogin without cookies`() {
        every { serverSecurityContextRepository.load(any()) } returns Mono.empty()

        webClient.get().uri("http://localhost/appLogin?redirectTo=/api/profile")
            .exchange()
            .expectStatus()
            .isFound
            .expectHeader().location("/oauth2/authorization/localhost")
            .expectCookie().exists("SPRING_REDIRECT_URI")
    }

    @Test
    fun `filter redirects without cookies and XMLHttpRequest`() {
        every { serverSecurityContextRepository.load(any()) } returns Mono.empty()

        webClient.get().uri("http://localhost/")
            .header("X-Requested-With", "XMLHttpRequest")
            .exchange()
            .expectStatus()
            .isUnauthorized
            .expectHeader().doesNotExist("Location")
            .expectBody<String>()
            .isEqualTo("/appLogin")
    }

    @Test
    fun `cookies fail with error in organization retrieval`() {
        everyValidSecurityContext()
        coEvery { authenticationStoreClient.getOrganizationByHostname("localhost") } throws RuntimeException("msg")
        val authenticationToken = ResourceUtils.resource("oauth2_authentication_token.json").readText()
        val authorizedClient = ResourceUtils.resource("simplified_oauth2_authorized_client.json").readText()

        webClient.get().uri("http://localhost/")
            .cookie(SPRING_SEC_SECURITY_CONTEXT, cookieSerializer.encodeCookie("localhost", authenticationToken))
            .cookie(SPRING_SEC_OAUTH2_AUTHZ_CLIENT, cookieSerializer.encodeCookie("localhost", authorizedClient))
            .exchange()
            .expectStatus()
            .isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR)
            .expectBody()
            .jsonPath("path").isEqualTo("/")
            .jsonPath("status").isEqualTo("500")
            .jsonPath("error").isEqualTo("Internal Server Error")
            .jsonPath("message").doesNotExist()
            .jsonPath("timestamp").exists()
            .jsonPath("requestId").exists()
    }

    @Test
    fun `cookies fail with missing organization`() {
        everyValidSecurityContext()
        coEvery { authenticationStoreClient.getOrganizationByHostname("localhost") } throws
            ResponseStatusException(HttpStatus.NOT_FOUND, "Hostname is not registered")
        val authenticationToken = ResourceUtils.resource("oauth2_authentication_token.json").readText()
        val authorizedClient = ResourceUtils.resource("simplified_oauth2_authorized_client.json").readText()

        webClient.get().uri("http://localhost/")
            .cookie(SPRING_SEC_SECURITY_CONTEXT, cookieSerializer.encodeCookie("localhost", authenticationToken))
            .cookie(SPRING_SEC_OAUTH2_AUTHZ_CLIENT, cookieSerializer.encodeCookie("localhost", authorizedClient))
            .exchange()
            .expectStatus().isNotFound
            .expectBody()
            .jsonPath("path").isEqualTo("/")
            .jsonPath("status").isEqualTo("404")
            .jsonPath("error").isEqualTo("Not Found")
            .jsonPath("message").doesNotExist()
            .jsonPath("timestamp").exists()
            .jsonPath("requestId").exists()
    }

    @Test
    fun `cookies fail with missing user`() {
        every { serverSecurityContextRepository.save(any(), null) } returns Mono.empty()
        everyValidSecurityContext()
        everyValidOrganization()
        coEvery {
            authenticationStoreClient.getUserByAuthenticationId("organizationTestId", "sub")
        } returns null

        val authenticationToken = ResourceUtils.resource("oauth2_authentication_token.json").readText()
        val authorizedClient = ResourceUtils.resource("simplified_oauth2_authorized_client.json").readText()

        webClient.get().uri("http://localhost/")
            .cookie(SPRING_SEC_SECURITY_CONTEXT, cookieSerializer.encodeCookie("localhost", authenticationToken))
            .cookie(SPRING_SEC_OAUTH2_AUTHZ_CLIENT, cookieSerializer.encodeCookie("localhost", authorizedClient))
            .exchange()
            .expectStatus().isNotFound
            .expectBody()
            .jsonPath("path").isEqualTo("/")
            .jsonPath("status").isEqualTo("404")
            .jsonPath("error").isEqualTo("Not Found")
            .jsonPath("message").doesNotExist()
            .jsonPath("timestamp").exists()
            .jsonPath("requestId").exists()
    }

    @Test
    fun `filter works with cookies and logout all`() {
        every { serverSecurityContextRepository.save(any(), null) } returns Mono.empty()
        everyValidSecurityContext()
        everyValidOrganization()
        coEvery { authenticationStoreClient.getUserByAuthenticationId("organizationTestId", "sub") } returns User(
            "userTestId",
            lastLogoutAllTimestamp = Instant.ofEpochSecond(1),
        )
        val authenticationToken = ResourceUtils.resource("oauth2_authentication_token.json").readText()
        val authorizedClient = ResourceUtils.resource("simplified_oauth2_authorized_client.json").readText()

        webClient.get().uri("http://localhost/")
            .cookie(SPRING_SEC_SECURITY_CONTEXT, cookieSerializer.encodeCookie("localhost", authenticationToken))
            .cookie(SPRING_SEC_OAUTH2_AUTHZ_CLIENT, cookieSerializer.encodeCookie("localhost", authorizedClient))
            .exchange()
            .expectStatus()
            .isFound
            .expectHeader().location("/oauth2/authorization/localhost")
            .expectCookie().doesNotExist(SPRING_SEC_SECURITY_CONTEXT)
            .expectCookie().valueEquals(SPRING_SEC_OAUTH2_AUTHZ_CLIENT, "")
    }

    @Test
    fun `filter works with bearer token`() {
        every { serverSecurityContextRepository.load(any()) } returns Mono.empty()
        everyValidOrganization()
        coEvery { authenticationStoreClient.getUserByApiToken("organizationTestId", "supersecuretoken") } returns User(
            "userTestId",
        )

        webClient.get().uri("http://localhost/")
            .header("Authorization", "Bearer supersecuretoken")
            .exchange()
            .expectStatus()
            .isOk
            .expectBody<String>()
            .isEqualTo("null <userTestId@organizationTestId>")
    }

    @Test
    fun `bearer token fails with error organization`() {
        every { serverSecurityContextRepository.load(any()) } returns Mono.empty()
        coEvery { authenticationStoreClient.getOrganizationByHostname("localhost") } throws RuntimeException("msg")

        webClient.get().uri("http://localhost/")
            .header("Authorization", "Bearer supersecuretoken")
            .exchange()
            .expectStatus()
            .isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR)
            .expectBody()
            .jsonPath("path").isEqualTo("/")
            .jsonPath("status").isEqualTo("500")
            .jsonPath("error").isEqualTo("Internal Server Error")
            .jsonPath("message").doesNotExist()
            .jsonPath("timestamp").exists()
            .jsonPath("requestId").exists()
    }

    @Test
    fun `bearer token fails with missing organization`() {
        every { serverSecurityContextRepository.load(any()) } returns Mono.empty()
        coEvery { authenticationStoreClient.getOrganizationByHostname("localhost") } throws
            ResponseStatusException(HttpStatus.NOT_FOUND, "Hostname is not registered")

        webClient.get().uri("http://localhost/")
            .header("Authorization", "Bearer supersecuretoken")
            .exchange()
            .expectStatus().isNotFound
            .expectBody()
            .jsonPath("path").isEqualTo("/")
            .jsonPath("status").isEqualTo("404")
            .jsonPath("error").isEqualTo("Not Found")
            .jsonPath("message").doesNotExist()
            .jsonPath("timestamp").exists()
            .jsonPath("requestId").exists()
    }

    @Test
    fun `bearer token fails with missing API token`() {
        every { serverSecurityContextRepository.load(any()) } returns Mono.empty()
        everyValidOrganization()
        coEvery { authenticationStoreClient.getUserByApiToken("organizationTestId", "supersecuretoken") } throws
            InvalidBearerTokenException("msg")

        webClient.get().uri("http://localhost/")
            .header("Authorization", "Bearer supersecuretoken")
            .exchange()
            .expectStatus()
            .isUnauthorized
            .expectHeader()
            .valueEquals(
                "WWW-Authenticate",
                "Bearer error=\"invalid_token\", " +
                    "error_description=\"msg\", " +
                    "error_uri=\"https://tools.ietf.org/html/rfc6750#section-3.1\""
            )
    }

    @Test
    fun `existing organization redirects to OIDC`() {
        every { serverSecurityContextRepository.load(any()) } returns Mono.empty()
        everyValidOrganization()

        webClient.get().uri("http://localhost/oauth2/authorization/localhost")
            .exchange()
            .expectStatus()
            .isFound
            .expectHeader().valueMatches(
                "Location",
                "http:\\/\\/localhost:3000\\/dex\\/auth\\?response_type=code&client_id=clientId&" +
                    "scope=openid%20profile&state=[^&]+&" +
                    "redirect_uri=http:\\/\\/localhost\\/login\\/oauth2\\/code\\/localhost&nonce=.+"
            )
    }

    @Test
    fun `missing organization fails to redirect to OIDC`() {
        every { serverSecurityContextRepository.load(any()) } returns Mono.empty()
        coEvery { authenticationStoreClient.getOrganizationByHostname("localhost") } throws
            ResponseStatusException(HttpStatus.NOT_FOUND, "Hostname is not registered")

        webClient.get().uri("http://localhost/oauth2/authorization/localhost")
            .exchange()
            .expectStatus().isNotFound
            .expectBody()
            .jsonPath("path").isEqualTo("/oauth2/authorization/localhost")
            .jsonPath("status").isEqualTo("404")
            .jsonPath("error").isEqualTo("Not Found")
            .jsonPath("message").doesNotExist()
            .jsonPath("timestamp").exists()
            .jsonPath("requestId").exists()
    }

    @Test
    fun `error from organization fails to redirect to OIDC`() {
        every { serverSecurityContextRepository.load(any()) } returns Mono.empty()
        coEvery { authenticationStoreClient.getOrganizationByHostname("localhost") } throws RuntimeException("msg")

        webClient.get().uri("http://localhost/oauth2/authorization/localhost")
            .exchange()
            .expectStatus()
            .isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR)
            .expectBody()
            .jsonPath("path").isEqualTo("/oauth2/authorization/localhost")
            .jsonPath("status").isEqualTo("500")
            .jsonPath("error").isEqualTo("Internal Server Error")
            .jsonPath("message").doesNotExist()
            .jsonPath("timestamp").exists()
            .jsonPath("requestId").exists()
    }

    @Test
    fun `filter redirects logout without cookies`() {
        every { serverSecurityContextRepository.load(any()) } returns Mono.empty()
        every { serverSecurityContextRepository.save(any(), null) } returns Mono.empty()

        webClient.get().uri("http://localhost/logout")
            .exchange()
            .expectStatus()
            .isFound
            .expectHeader().location("/")
            .expectCookie().exists("SPRING_REDIRECT_URI")
    }

    @Test
    fun `filter redirects logout with cookies`() {
        everyValidSecurityContext()
        every { serverSecurityContextRepository.save(any(), null) } returns Mono.empty()
        everyValidOrganization()
        coEvery { authenticationStoreClient.getUserByAuthenticationId("organizationTestId", "sub") } returns User(
            "userTestId",
        )
        val authenticationToken = ResourceUtils.resource("oauth2_authentication_token.json").readText()
        val authorizedClient = ResourceUtils.resource("simplified_oauth2_authorized_client.json").readText()

        webClient.get().uri("http://localhost/logout")
            .cookie(SPRING_SEC_SECURITY_CONTEXT, cookieSerializer.encodeCookie("localhost", authenticationToken))
            .cookie(SPRING_SEC_OAUTH2_AUTHZ_CLIENT, cookieSerializer.encodeCookie("localhost", authorizedClient))
            .exchange()
            .expectStatus()
            .isFound
            .expectHeader().location("/")
            .expectCookie().exists("SPRING_REDIRECT_URI")
    }

    @Test
    fun `POST logout ends with 405`() {
        every { serverSecurityContextRepository.load(any()) } returns Mono.empty()
        every { serverSecurityContextRepository.save(any(), null) } returns Mono.empty()

        webClient.post().uri("http://localhost/logout")
            .exchange()
            .expectStatus()
            .isEqualTo(HttpStatus.METHOD_NOT_ALLOWED)
            .expectCookie().exists("SPRING_REDIRECT_URI")
    }

    @Test
    fun `POST logout all ends with 405`() {
        every { serverSecurityContextRepository.load(any()) } returns Mono.empty()
        every { serverSecurityContextRepository.save(any(), null) } returns Mono.empty()

        webClient.post().uri("http://localhost/logout/all")
            .exchange()
            .expectStatus()
            .isEqualTo(HttpStatus.METHOD_NOT_ALLOWED)
            .expectCookie().exists("SPRING_REDIRECT_URI")
    }

    private fun everyValidSecurityContext() {
        every { serverSecurityContextRepository.load(any()) } returns Mono.just(
            OidcIdToken(
                "tokenValue",
                Instant.EPOCH,
                Instant.EPOCH.plusSeconds(1),
                mapOf(
                    IdTokenClaimNames.SUB to "sub",
                    IdTokenClaimNames.IAT to Instant.EPOCH
                )
            )
        ).map {
            SecurityContextImpl(
                OAuth2AuthenticationToken(
                    DefaultOidcUser(
                        listOf(OidcUserAuthority(it)),
                        it
                    ),
                    emptyList(),
                    "localhost"
                )
            )
        }
    }

    private fun everyValidOrganization() {
        coEvery { authenticationStoreClient.getOrganizationByHostname("localhost") } returns Organization(
            "organizationTestId",
            oauthClientId = "clientId",
            oauthClientSecret = "clientSecret",
        )
    }

    @Configuration
    class Config {
        @MockkBean
        lateinit var serverSecurityContextRepository: ServerSecurityContextRepository

        @MockkBean
        lateinit var authenticationStoreClient: AuthenticationStoreClient

        @Bean
        fun dummyController() = DummyController()

        @Bean
        fun userContextHolder() = CoroutineUserContextHolder
    }

    data class UserContext(
        override val organizationId: String,
        override val userId: String,
        val userName: String?,
    ) : AuthenticationUserContext

    object CoroutineUserContextHolder : UserContextHolder<UserContext> {
        override suspend fun getContext(): UserContext? {
            return coroutineContext[ReactorContext]
                ?.context
                ?.getOrDefault<UserContext>(UserContext::class.java, null)
        }

        override suspend fun setContext(organizationId: String, userId: String, userName: String?): ReactorContext {
            return (coroutineContext[ReactorContext]?.context ?: Context.empty())
                .putAll(
                    Context.of(UserContext::class.java, UserContext(organizationId, userId, userName)) as ContextView
                )
                .asCoroutineContext()
        }
    }

    @RestController
    class DummyController {

        @GetMapping("/")
        suspend fun getDummy(): ResponseEntity<String> = coroutineScope {
            val authContext = coroutineContext[ReactorContext]?.context?.get(UserContext::class.java)!!
            ResponseEntity.ok(
                "${authContext.userName} <${authContext.userId}@${authContext.organizationId}>"
            )
        }
    }
}

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
package com.gooddata.oauth2.server.servlet

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
import net.javacrumbs.jsonunit.core.util.ResourceUtils
import org.hamcrest.Matchers
import org.intellij.lang.annotations.Language
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest
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
import org.springframework.security.web.context.SecurityContextRepository
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import org.springframework.test.web.servlet.post
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.server.ResponseStatusException
import strikt.api.expectThrows
import strikt.assertions.isEqualTo
import java.time.Duration
import java.time.Instant
import javax.servlet.http.Cookie

@WebMvcTest
@Import(OAuth2AutoConfiguration::class, UserContextWebMvcTest.Config::class)
class UserContextWebMvcTest(
    @Autowired private val mockMvc: MockMvc,
    @Autowired private val securityContextRepository: SecurityContextRepository,
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
        every { securityContextRepository.saveContext(any(), any(), any()) } returns Unit
        every { securityContextRepository.containsContext(any()) } returns true
        everyValidOrganization()
        coEvery { authenticationStoreClient.getUserByAuthenticationId("organizationId", "sub") } returns User(
            "userId",
        )
        coEvery { authenticationStoreClient.getCookieSecurityProperties("organizationId") } returns
            CookieSecurityProperties(
                keySet = CleartextKeysetHandle.read(JsonKeysetReader.withBytes(keyset.toByteArray())),
                lastRotation = Instant.now(),
                rotationInterval = Duration.ofDays(1),
            )
        val authenticationToken = ResourceUtils.resource("oauth2_authentication_token.json").readText()
        val authorizedClient = ResourceUtils.resource("simplified_oauth2_authorized_client.json").readText()

        mockMvc.get("http://localhost/") {
            cookie(
                Cookie(SPRING_SEC_SECURITY_CONTEXT, cookieSerializer.encodeCookie("localhost", authenticationToken)),
                Cookie(SPRING_SEC_OAUTH2_AUTHZ_CLIENT, cookieSerializer.encodeCookie("localhost", authorizedClient)),
            )
        }.andExpect {
            status { isOk() }
            content { string("sub <userId@organizationId>") }
        }
    }

    @Test
    fun `filter redirects without cookies`() {
        every { securityContextRepository.loadContext(any()) } returns SecurityContextImpl()
        every { securityContextRepository.saveContext(any(), any(), any()) } returns Unit
        every { securityContextRepository.containsContext(any()) } returns false

        mockMvc.get("http://localhost/")
            .andExpect {
                status { isFound() }
                header { string("Location", "/oauth2/authorization/localhost") }
                cookie { exists("SPRING_REDIRECT_URI") }
            }
    }

    @Test
    fun `filter redirects without cookies and XMLHttpRequest`() {
        every { securityContextRepository.loadContext(any()) } returns SecurityContextImpl()
        every { securityContextRepository.saveContext(any(), any(), any()) } returns Unit
        every { securityContextRepository.containsContext(any()) } returns false

        mockMvc.get("http://localhost/") {
            header("X-Requested-With", "XMLHttpRequest")
        }.andExpect {
            status { isUnauthorized() }
            header { doesNotExist("Location") }
            content { string("/appLogin") }
        }
    }

    @Test
    fun `cookies fail with error in organization retrieval`() {
        everyValidSecurityContext()
        every { securityContextRepository.saveContext(any(), any(), any()) } returns Unit
        every { securityContextRepository.containsContext(any()) } returns true
        coEvery { authenticationStoreClient.getOrganizationByHostname("localhost") } throws RuntimeException("msg")
        val authenticationToken = ResourceUtils.resource("oauth2_authentication_token.json").readText()
        val authorizedClient = ResourceUtils.resource("simplified_oauth2_authorized_client.json").readText()

        // MockMvc does not use servlet container for testing that is normally responsible for exception translation
        // so the exception just bubbles up
        expectThrows<RuntimeException> {
            mockMvc.get("http://localhost/") {
                cookie(
                    Cookie(
                        SPRING_SEC_SECURITY_CONTEXT,
                        cookieSerializer.encodeCookie("localhost", authenticationToken)
                    ),
                    Cookie(
                        SPRING_SEC_OAUTH2_AUTHZ_CLIENT,
                        cookieSerializer.encodeCookie("localhost", authorizedClient)
                    ),
                )
            }
        }
    }

    @Test
    fun `cookies fail with missing organization`() {
        everyValidSecurityContext()
        every { securityContextRepository.saveContext(any(), any(), any()) } returns Unit
        every { securityContextRepository.containsContext(any()) } returns true
        coEvery { authenticationStoreClient.getOrganizationByHostname("localhost") } throws
            ResponseStatusException(HttpStatus.NOT_FOUND, "Hostname is not registered")
        val authenticationToken = ResourceUtils.resource("oauth2_authentication_token.json").readText()
        val authorizedClient = ResourceUtils.resource("simplified_oauth2_authorized_client.json").readText()

        mockMvc.get("http://localhost/") {
            cookie(
                Cookie(SPRING_SEC_SECURITY_CONTEXT, cookieSerializer.encodeCookie("localhost", authenticationToken)),
                Cookie(SPRING_SEC_OAUTH2_AUTHZ_CLIENT, cookieSerializer.encodeCookie("localhost", authorizedClient)),
            )
        }.andExpect {
            status {
                isNotFound()
                reason("Hostname is not registered")
            }
            header { doesNotExist("Location") }
            content {
                string("")
            }
        }
    }

    @Test
    fun `cookies fail with missing user`() {
        everyValidSecurityContext()
        every { securityContextRepository.saveContext(any(), any(), any()) } returns Unit
        every { securityContextRepository.containsContext(any()) } returns true
        everyValidOrganization()
        coEvery {
            authenticationStoreClient.getUserByAuthenticationId("organizationId", "sub")
        } returns null
        val authenticationToken = ResourceUtils.resource("oauth2_authentication_token.json").readText()
        val authorizedClient = ResourceUtils.resource("simplified_oauth2_authorized_client.json").readText()

        mockMvc.get("http://localhost/") {
            cookie(
                Cookie(SPRING_SEC_SECURITY_CONTEXT, cookieSerializer.encodeCookie("localhost", authenticationToken)),
                Cookie(SPRING_SEC_OAUTH2_AUTHZ_CLIENT, cookieSerializer.encodeCookie("localhost", authorizedClient)),
            )
        }.andExpect {
            status {
                isNotFound()
                reason("User is not registered")
            }
            header { doesNotExist("Location") }
            content {
                string("")
            }
        }
    }

    @Test
    fun `filter works with cookies and logout all`() {
        everyValidSecurityContext()
        every { securityContextRepository.saveContext(any(), any(), any()) } returns Unit
        every { securityContextRepository.containsContext(any()) } returns true
        everyValidOrganization()
        coEvery { authenticationStoreClient.getUserByAuthenticationId("organizationId", "sub") } returns User(
            "userId",
            lastLogoutAllTimestamp = Instant.ofEpochSecond(1),
        )
        val authenticationToken = ResourceUtils.resource("oauth2_authentication_token.json").readText()
        val authorizedClient = ResourceUtils.resource("simplified_oauth2_authorized_client.json").readText()

        mockMvc.get("http://localhost/") {
            cookie(
                Cookie(SPRING_SEC_SECURITY_CONTEXT, cookieSerializer.encodeCookie("localhost", authenticationToken)),
                Cookie(SPRING_SEC_OAUTH2_AUTHZ_CLIENT, cookieSerializer.encodeCookie("localhost", authorizedClient)),
            )
        }.andExpect {
            status { isFound() }
            redirectedUrl("/oauth2/authorization/localhost")
        }
    }

    @Test
    fun `filter works with bearer token`() {
        every { securityContextRepository.loadContext(any()) } returns SecurityContextImpl()
        every { securityContextRepository.saveContext(any(), any(), any()) } returns Unit
        every { securityContextRepository.containsContext(any()) } returns false
        everyValidOrganization()
        coEvery { authenticationStoreClient.getUserByApiToken("organizationId", "supersecuretoken") } returns User(
            "userId",
        )

        mockMvc.get("http://localhost/") {
            header("Authorization", "Bearer supersecuretoken")
        }.andExpect {
            status { isOk() }
            content { string("null <userId@organizationId>") }
        }
    }

    @Test
    fun `bearer token fails with error organization`() {
        every { securityContextRepository.loadContext(any()) } returns SecurityContextImpl()
        every { securityContextRepository.saveContext(any(), any(), any()) } returns Unit
        every { securityContextRepository.containsContext(any()) } returns false
        coEvery { authenticationStoreClient.getOrganizationByHostname("localhost") } throws RuntimeException("msg")

        // MockMvc does not use servlet container for testing that is normally responsible for exception translation
        // so the exception just bubbles up
        expectThrows<RuntimeException> {
            mockMvc.get("http://localhost/") {
                header("Authorization", "Bearer supersecuretoken")
            }
        }
    }

    @Test
    fun `bearer token fails with missing organization`() {
        every { securityContextRepository.loadContext(any()) } returns SecurityContextImpl()
        every { securityContextRepository.saveContext(any(), any(), any()) } returns Unit
        every { securityContextRepository.containsContext(any()) } returns false
        coEvery { authenticationStoreClient.getOrganizationByHostname("localhost") } throws
            ResponseStatusException(HttpStatus.NOT_FOUND, "Hostname is not registered")

        mockMvc.get("http://localhost/") {
            header("Authorization", "Bearer supersecuretoken")
        }.andExpect {
            status {
                isNotFound()
                reason("Hostname is not registered")
            }
            header { doesNotExist("Location") }
            content {
                string("")
            }
        }
    }

    @Test
    fun `bearer token fails with missing API token`() {
        every { securityContextRepository.loadContext(any()) } returns SecurityContextImpl()
        every { securityContextRepository.saveContext(any(), any(), any()) } returns Unit
        every { securityContextRepository.containsContext(any()) } returns false
        everyValidOrganization()
        coEvery { authenticationStoreClient.getUserByApiToken("organizationId", "supersecuretoken") } throws
            RuntimeException("msg")

        // MockMvc does not use servlet container for testing that is normally responsible for exception translation
        // so the exception just bubbles up
        expectThrows<RuntimeException> {
            mockMvc.get("http://localhost/") {
                header("Authorization", "Bearer supersecuretoken")
            }
        }
    }

    @Test
    fun `existing organization redirects to OIDC`() {
        every { securityContextRepository.loadContext(any()) } returns SecurityContextImpl()
        every { securityContextRepository.saveContext(any(), any(), any()) } returns Unit
        every { securityContextRepository.containsContext(any()) } returns false
        everyValidOrganization()

        mockMvc.get("http://localhost/oauth2/authorization/localhost")
            .andExpect {
                status { isFound() }
                header {
                    string(
                        "Location",
                        Matchers.matchesRegex(
                            "http:\\/\\/localhost:3000\\/dex\\/auth\\?response_type=code&client_id=clientId&" +
                                "scope=openid%20profile&state=[^&]+&" +
                                "redirect_uri=http:\\/\\/localhost\\/login\\/oauth2\\/code\\/localhost&nonce=.+"
                        )
                    )
                }
            }
    }

    @Test
    fun `missing organization fails to redirect to OIDC`() {
        every { securityContextRepository.loadContext(any()) } returns SecurityContextImpl()
        every { securityContextRepository.saveContext(any(), any(), any()) } returns Unit
        every { securityContextRepository.containsContext(any()) } returns false
        coEvery { authenticationStoreClient.getOrganizationByHostname("localhost") } throws ResponseStatusException(
            HttpStatus.NOT_FOUND
        )

        mockMvc.get("http://localhost/oauth2/authorization/localhost")
            .andExpect {
                status { isInternalServerError() }
                content { string("") }
            }
    }

    @Test
    fun `error from organization fails to redirect to OIDC`() {
        every { securityContextRepository.loadContext(any()) } returns SecurityContextImpl()
        every { securityContextRepository.saveContext(any(), any(), any()) } returns Unit
        every { securityContextRepository.containsContext(any()) } returns false
        coEvery { authenticationStoreClient.getOrganizationByHostname("localhost") } throws RuntimeException("msg")

        mockMvc.get("http://localhost/oauth2/authorization/localhost")
            .andExpect {
                status { isInternalServerError() }
                content { string("") }
            }
    }

    @Test
    fun `filter redirects logout without cookies`() {
        every { securityContextRepository.loadContext(any()) } returns SecurityContextImpl()
        every { securityContextRepository.saveContext(any(), any(), any()) } returns Unit
        every { securityContextRepository.containsContext(any()) } returns false

        mockMvc.get("http://localhost/logout")
            .andExpect {
                status { isFound() }
                header { string("Location", "/") }
            }
    }

    @Test
    fun `filter redirects logout with cookies`() {
        everyValidSecurityContext()
        every { securityContextRepository.saveContext(any(), any(), any()) } returns Unit
        every { securityContextRepository.containsContext(any()) } returns true
        everyValidOrganization()
        coEvery { authenticationStoreClient.getUserByAuthenticationId("organizationId", "sub") } returns User(
            "userId",
        )
        val authenticationToken = ResourceUtils.resource("oauth2_authentication_token.json").readText()
        val authorizedClient = ResourceUtils.resource("simplified_oauth2_authorized_client.json").readText()

        mockMvc.get("http://localhost/logout") {
            cookie(
                Cookie(SPRING_SEC_SECURITY_CONTEXT, cookieSerializer.encodeCookie("localhost", authenticationToken)),
                Cookie(SPRING_SEC_OAUTH2_AUTHZ_CLIENT, cookieSerializer.encodeCookie("localhost", authorizedClient)),
            )
        }.andExpect {
            status { isFound() }
            header { string("Location", "/") }
        }
    }

    @Test
    fun `POST logout ends with 405`() {
        every { securityContextRepository.loadContext(any()) } returns SecurityContextImpl()
        every { securityContextRepository.saveContext(any(), any(), any()) } returns Unit
        every { securityContextRepository.containsContext(any()) } returns false

        expectThrows<ResponseStatusException> {
            mockMvc.post("http://localhost/logout")
                .andExpect {
                    status { isFound() }
                    header { string("Location", "/") }
                }
        }.get { status }.isEqualTo(HttpStatus.METHOD_NOT_ALLOWED)
    }

    private fun everyValidSecurityContext() {
        every { securityContextRepository.loadContext(any()) } returns OidcIdToken(
            "tokenValue",
            Instant.EPOCH,
            Instant.EPOCH.plusSeconds(1),
            mapOf(
                IdTokenClaimNames.SUB to "sub",
                IdTokenClaimNames.IAT to Instant.EPOCH
            )
        ).let {
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
            "organizationId",
            oauthClientId = "clientId",
            oauthClientSecret = "clientSecret",
        )
    }

    @Configuration
    class Config {
        @MockkBean
        lateinit var securityContextRepository: SecurityContextRepository

        @MockkBean
        lateinit var authenticationStoreClient: AuthenticationStoreClient

        @Bean
        fun dummyController() = DummyController()

        @Bean
        fun userContextHolder() = ThreadLocalUserContextHolder
    }

    object ThreadLocalUserContextHolder : UserContextHolder {
        private val contextHolder = ThreadLocal<UserContext>()

        override fun setContext(organizationId: String, userId: String, userName: String?) =
            contextHolder.set(UserContext(organizationId, userId, userName))

        override fun clearContext() = contextHolder.remove()
        fun getContext(): UserContext? = contextHolder.get()
    }

    data class UserContext(
        val organizationId: String,
        val userId: String,
        val userName: String?,
    )

    @RestController
    class DummyController {

        @GetMapping("/")
        fun getDummy(): ResponseEntity<String> {
            return ResponseEntity.ok(
                ThreadLocalUserContextHolder.getContext()!!.let {
                    "${it.userName} <${it.userId}@${it.organizationId}>"
                }
            )
        }
    }
}

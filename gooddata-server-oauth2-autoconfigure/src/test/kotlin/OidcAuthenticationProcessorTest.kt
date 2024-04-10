/*
 * Copyright 2023 GoodData Corporation
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

import com.gooddata.oauth2.server.OrganizationWebFilter.Companion.orgContextWrite
import io.mockk.called
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.jupiter.api.Test
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException
import org.springframework.security.web.server.ServerAuthenticationEntryPoint
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono
import reactor.test.StepVerifier
import reactor.util.context.Context
import java.time.Instant

class OidcAuthenticationProcessorTest {

    private val client: AuthenticationStoreClient = mockk()

    private val authenticationEntryPoint: ServerAuthenticationEntryPoint = mockk()

    private val serverLogoutHandler: ServerLogoutHandler = mockk()

    private val userContextProvider: ReactorUserContextProvider = mockk()

    private val oidcAuthenticationProcessor =
        OidcAuthenticationProcessor(client, authenticationEntryPoint, serverLogoutHandler, userContextProvider)

    @Test
    fun `user context is stored for Oidc authentication`() {
        val organization = Organization(ORG_ID)
        val idToken = OidcIdToken(
            "tokenValue",
            Instant.EPOCH,
            Instant.EPOCH.plusSeconds(1),
            mapOf(
                IdTokenClaimNames.SUB to "sub",
                IdTokenClaimNames.IAT to Instant.EPOCH
            )
        )
        val authenticationToken = OAuth2AuthenticationToken(
            DefaultOidcUser(
                listOf(OidcUserAuthority(idToken)),
                idToken
            ),
            emptyList(),
            HOSTNAME
        )

        mockOrganization(client, HOSTNAME, organization)
        mockUserByAuthId(client, ORG_ID, "sub", User(USER_ID))
        coEvery { userContextProvider.getContextView(any(), any(), any(), any()) } returns Context.empty()

        val webFilterChain = mockk<WebFilterChain> {
            every { filter(any()) } returns Mono.empty()
        }

        val mono = oidcAuthenticationProcessor.authenticate(authenticationToken, mockk(), webFilterChain)
            .orgContextWrite(organization)

        StepVerifier
            .create(mono)
            .verifyComplete()

        verify { serverLogoutHandler wasNot called }
        verify { authenticationEntryPoint wasNot called }
        verify(exactly = 1) { webFilterChain.filter(any()) }
        coVerify(exactly = 1) {
            userContextProvider.getContextView(
                ORG_ID,
                USER_ID,
                "sub",
                null
            )
        }
    }

    @Test
    fun `user context is stored for Oidc authentication using non-default subject claim`() {
        val organization = Organization(id = ORG_ID, oauthSubjectIdClaim = OID_SUBJECT_ID_CLAIM_NAME)
        val idToken = OidcIdToken(
            "tokenValue",
            Instant.EPOCH,
            Instant.EPOCH.plusSeconds(1),
            mapOf(
                IdTokenClaimNames.SUB to "non-sub",
                OID_SUBJECT_ID_CLAIM_NAME to "sub",
                IdTokenClaimNames.IAT to Instant.EPOCH
            )
        )
        val authenticationToken = OAuth2AuthenticationToken(
            DefaultOidcUser(
                listOf(OidcUserAuthority(idToken)),
                idToken
            ),
            emptyList(),
            HOSTNAME
        )

        mockOrganization(client, HOSTNAME, organization)
        mockUserByAuthId(client, ORG_ID, "sub", User(USER_ID))
        coEvery { userContextProvider.getContextView(any(), any(), any(), null) } returns Context.empty()

        val webFilterChain = mockk<WebFilterChain> {
            every { filter(any()) } returns Mono.empty()
        }

        val mono = oidcAuthenticationProcessor.authenticate(authenticationToken, mockk(), webFilterChain)
            .orgContextWrite(organization)

        StepVerifier
            .create(mono)
            .verifyComplete()

        verify { serverLogoutHandler wasNot called }
        verify { authenticationEntryPoint wasNot called }
        verify(exactly = 1) { webFilterChain.filter(any()) }
        coVerify(exactly = 1) { userContextProvider.getContextView(ORG_ID, USER_ID, "non-sub", null) }
    }

    @Test
    fun `Oidc authentication should fail when subject claim is missing`() {
        val organization = Organization(id = ORG_ID, oauthSubjectIdClaim = OID_SUBJECT_ID_CLAIM_NAME)
        val idToken = OidcIdToken(
            "tokenValue",
            Instant.EPOCH,
            Instant.EPOCH.plusSeconds(1),
            mapOf(
                IdTokenClaimNames.SUB to "non-sub",
                IdTokenClaimNames.IAT to Instant.EPOCH
            )
        )
        val authenticationToken = OAuth2AuthenticationToken(
            DefaultOidcUser(
                listOf(OidcUserAuthority(idToken)),
                idToken
            ),
            emptyList(),
            HOSTNAME
        )

        mockOrganization(client, HOSTNAME, organization)
        mockUserByAuthId(client, ORG_ID, "sub", User(USER_ID))
        coEvery { userContextProvider.getContextView(any(), any(), any(), any()) } returns Context.empty()

        val webFilterChain = mockk<WebFilterChain> {
            every { filter(any()) } returns Mono.empty()
        }

        val mono = oidcAuthenticationProcessor.authenticate(authenticationToken, mockk(), webFilterChain)
            .orgContextWrite(organization)

        StepVerifier
            .create(mono)
            .verifyError(InvalidBearerTokenException::class.java)
    }

    @Test
    fun `user context is not processed when logoutAll has been triggered`() {
        val idToken = OidcIdToken(
            "tokenValue",
            Instant.EPOCH,
            Instant.EPOCH.plusSeconds(1),
            mapOf(
                IdTokenClaimNames.SUB to "sub",
                IdTokenClaimNames.IAT to Instant.EPOCH
            )
        )
        val authenticationToken = OAuth2AuthenticationToken(
            DefaultOidcUser(
                listOf(OidcUserAuthority(idToken)),
                idToken
            ),
            emptyList(),
            HOSTNAME
        )

        every { serverLogoutHandler.logout(any(), any()) } returns Mono.empty()
        every { authenticationEntryPoint.commence(any(), any()) } returns Mono.empty()
        mockOrganization(client, HOSTNAME, Organization(ORG_ID))
        mockUserByAuthId(client, ORG_ID, "sub", User(USER_ID, lastLogoutAllTimestamp = Instant.ofEpochSecond(1)))

        val webFilterChain = mockk<WebFilterChain>()

        oidcAuthenticationProcessor.authenticate(authenticationToken, mockk(), webFilterChain)
            .orgContextWrite(ORGANIZATION)
            .block()

        verify(exactly = 1) { serverLogoutHandler.logout(any(), any()) }
        verify(exactly = 1) { authenticationEntryPoint.commence(any(), any()) }
        verify { webFilterChain wasNot called }
        verify { userContextProvider wasNot called }
    }

    companion object {
        private const val ORG_ID = "organizationId"
        private const val HOSTNAME = "hostname"
        private const val USER_ID = "userId"
        private val ORGANIZATION = Organization(ORG_ID)
        private const val OID_SUBJECT_ID_CLAIM_NAME = "oid"
    }
}

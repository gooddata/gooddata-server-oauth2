/*
 * Copyright 2024 GoodData Corporation
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

import com.gooddata.oauth2.server.JitProvisioningAuthenticationSuccessHandler.Claims.GD_USER_GROUPS
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import java.util.stream.Stream
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.core.oidc.StandardClaimNames.EMAIL
import org.springframework.security.oauth2.core.oidc.StandardClaimNames.FAMILY_NAME
import org.springframework.security.oauth2.core.oidc.StandardClaimNames.GIVEN_NAME
import org.springframework.security.web.server.WebFilterExchange
import reactor.core.publisher.Mono
import strikt.api.expectThat
import strikt.api.expectThrows
import strikt.assertions.isEqualTo
import strikt.assertions.isNull

class JitProvisioningAuthenticationSuccessHandlerTest {

    private val client: AuthenticationStoreClient = mockk()
    private val exchange: WebFilterExchange = mockk {
        coEvery { exchange.request.uri.host } returns HOST
    }
    private val authentication: OAuth2AuthenticationToken = mockk {
        every { principal } returns mockk {
            every { attributes } returns mapOf(
                SUB to SUB,
                EMAIL to EMAIL,
                GIVEN_NAME to GIVEN_NAME,
                FAMILY_NAME to FAMILY_NAME
            )
        }
    }

    @Test
    fun `should skip JIT provisioning if disabled on both org and orgSetting level`() {
        // given
        val handler = JitProvisioningAuthenticationSuccessHandler(client)

        // when
        mockOrganization(client, HOST, Organization(id = ORG_ID, jitEnabled = false))
        every { client.getJitProvisioningSetting(ORG_ID) } returns Mono.empty()

        // then
        expectThat(
            handler.onAuthenticationSuccess(exchange, authentication)
                .block()
        ).isNull()

        coVerify { client.getOrganizationByHostname(HOST) }
        coVerify { client.getJitProvisioningSetting(ORG_ID) }
    }

    @Test
    fun `should raise an exception when JIT enabled on Organization lvl and mandatory attributes are missing`() {
        // given
        val handler = JitProvisioningAuthenticationSuccessHandler(client)

        // when
        mockOrganization(client, HOST, Organization(id = ORG_ID, jitEnabled = true))

        val authentication: OAuth2AuthenticationToken = mockk {
            every { principal } returns mockk {
                every { attributes } returns emptyMap()
            }
        }
        // then
        expectThrows<JitProvisioningAuthenticationSuccessHandler.MissingMandatoryClaimsException> {
            handler.onAuthenticationSuccess(exchange, authentication)
                .block()
        }.and {
            get { message }.isEqualTo(
                "401 UNAUTHORIZED \"Authorization failed. Missing mandatory claims: [given_name, family_name, email]\""
            )
        }
    }

    @Test
    fun `should raise an exception when JIT enabled via OrganizationSettings and mandatory attributes are missing`() {
        // given
        val handler = JitProvisioningAuthenticationSuccessHandler(client)

        // when
        mockOrganization(client, HOST, Organization(id = ORG_ID, jitEnabled = false))
        every { client.getJitProvisioningSetting(ORG_ID) } returns Mono.just(JitProvisioningSetting(enabled = true))

        val authentication: OAuth2AuthenticationToken = mockk {
            every { principal } returns mockk {
                every { attributes } returns emptyMap()
            }
        }
        // then
        expectThrows<JitProvisioningAuthenticationSuccessHandler.MissingMandatoryClaimsException> {
            handler.onAuthenticationSuccess(exchange, authentication)
                .block()
        }.and {
            get { message }.isEqualTo(
                "401 UNAUTHORIZED \"Authorization failed. Missing mandatory claims: [given_name, family_name, email]\""
            )
        }
    }

    @Test
    fun `should perform JIT provisioning when JIT enabled on Organization lvl and user does not exist`() {
        // given
        val handler = JitProvisioningAuthenticationSuccessHandler(client)

        // when
        mockOrganization(client, HOST, Organization(id = ORG_ID, oauthSubjectIdClaim = SUB, jitEnabled = true))
        mockUserByAuthId(client, ORG_ID, SUB, null)
        every { client.createUser(ORG_ID, SUB, GIVEN_NAME, FAMILY_NAME, EMAIL, emptyList()) } returns
            Mono.just(mockk<User> { every { id } returns USER_ID })

        // then
        expectThat(
            handler.onAuthenticationSuccess(exchange, authentication)
                .block()
        ).isNull()

        coVerify { client.getOrganizationByHostname(HOST) }
        coVerify { client.getUserByAuthenticationId(ORG_ID, SUB) }
        coVerify { client.createUser(ORG_ID, SUB, GIVEN_NAME, FAMILY_NAME, EMAIL, emptyList()) }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("jitOptions")
    fun `should perform JIT provisioning when JIT enabled via OrganizationSetting and user does not exist`(
        case: String,
        userGroupsInAuthToken: List<String>?,
        userGroupsInOrgSetting: List<String>?,
        expectedUserGroups: List<String>
    ) {
        // given
        val handler = JitProvisioningAuthenticationSuccessHandler(client)

        val tokenClaims = if (userGroupsInAuthToken != null) {
            mapOf(
                SUB to SUB,
                EMAIL to EMAIL,
                GIVEN_NAME to GIVEN_NAME,
                FAMILY_NAME to FAMILY_NAME,
                GD_USER_GROUPS to userGroupsInAuthToken
            )
        } else {
            mapOf(
                SUB to SUB,
                EMAIL to EMAIL,
                GIVEN_NAME to GIVEN_NAME,
                FAMILY_NAME to FAMILY_NAME,
            )
        }

        val authentication: OAuth2AuthenticationToken = mockk {
            every { principal } returns mockk {
                every { attributes } returns tokenClaims
            }
        }

        // when
        mockOrganization(client, HOST, Organization(id = ORG_ID, oauthSubjectIdClaim = SUB, jitEnabled = false))
        every { client.getJitProvisioningSetting(ORG_ID) } returns
            Mono.just(JitProvisioningSetting(enabled = true, userGroupsDefaults = userGroupsInOrgSetting))
        mockUserByAuthId(client, ORG_ID, SUB, null)
        every { client.createUser(ORG_ID, SUB, GIVEN_NAME, FAMILY_NAME, EMAIL, expectedUserGroups) } returns
            Mono.just(mockk<User> { every { id } returns USER_ID })

        // then
        expectThat(
            handler.onAuthenticationSuccess(exchange, authentication)
                .block()
        ).isNull()

        coVerify { client.getOrganizationByHostname(HOST) }
        coVerify { client.getJitProvisioningSetting(ORG_ID) }
        coVerify { client.getUserByAuthenticationId(ORG_ID, SUB) }
        coVerify { client.createUser(ORG_ID, SUB, GIVEN_NAME, FAMILY_NAME, EMAIL, expectedUserGroups) }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("users")
    fun `should test user patching`(
        case: String,
        user: User,
        userGroupsInAuthToken: List<String>?,
        patchCount: Int
    ) {
        // given
        val handler = JitProvisioningAuthenticationSuccessHandler(client)

        val usersCurrentUserGroups = user.userGroups

        val tokenClaims = if (userGroupsInAuthToken != null) {
            mapOf(
                SUB to SUB,
                EMAIL to EMAIL,
                GIVEN_NAME to GIVEN_NAME,
                FAMILY_NAME to FAMILY_NAME,
                GD_USER_GROUPS to userGroupsInAuthToken
            )
        } else {
            mapOf(
                SUB to SUB,
                EMAIL to EMAIL,
                GIVEN_NAME to GIVEN_NAME,
                FAMILY_NAME to FAMILY_NAME,
            )
        }

        val authentication: OAuth2AuthenticationToken = mockk {
            every { principal } returns mockk {
                every { attributes } returns tokenClaims
            }
        }

        // when
        mockOrganization(client, HOST, Organization(id = ORG_ID, oauthSubjectIdClaim = SUB, jitEnabled = true))
        mockUserByAuthId(client, ORG_ID, SUB, user)
        val userSlot = slot<User>()
        every { client.patchUser(ORG_ID, capture(userSlot)) } returns Mono.just(mockk())

        // then
        expectThat(
            handler.onAuthenticationSuccess(exchange, authentication)
                .block()
        ).isNull()

        coVerify { client.getOrganizationByHostname(HOST) }
        coVerify { client.getUserByAuthenticationId(ORG_ID, SUB) }
        coVerify(exactly = patchCount) { client.patchUser(ORG_ID, any()) }

        if (patchCount != 0) {
            if (userGroupsInAuthToken != null) {
                expectThat(userSlot.captured.userGroups).isEqualTo(userGroupsInAuthToken)
            } else {
                expectThat(userSlot.captured.userGroups).isEqualTo(usersCurrentUserGroups)
            }
        }
    }

    companion object {

        private const val ORG_ID = "orgId"
        private const val SUB = "sub"
        private const val HOST = "gooddata.com"
        private const val USER_ID = "userId"

        @JvmStatic
        fun jitOptions() = Stream.of(
            Arguments.of(
                "without user groups",
                emptyList<String>(),
                emptyList<String>(),
                emptyList<String>(),
            ),
            Arguments.of(
                "with default user groups",
                null,
                listOf("defaultUserGroup"),
                listOf("defaultUserGroup"),
            ),
            Arguments.of(
                "with default user groups and user groups in token",
                listOf("adminUserGroup", "secondUserGroup"),
                listOf("defaultUserGroup"),
                listOf("adminUserGroup", "secondUserGroup"),
            )
        )

        @JvmStatic
        fun users() = Stream.of(
            Arguments.of(
                "should update user when users lastname is changed",
                User(
                    USER_ID,
                    null,
                    firstname = GIVEN_NAME,
                    lastname = "NewFamilyName",
                    email = EMAIL,
                    userGroups = listOf("defaultUserGroup")
                ),
                null,
                1
            ),
            Arguments.of(
                "should update user when users userGroups are changed",
                User(
                    USER_ID,
                    null,
                    firstname = GIVEN_NAME,
                    lastname = FAMILY_NAME,
                    email = EMAIL,
                    userGroups = listOf("defaultUserGroup")
                ),
                emptyList<String>(),
                1
            ),
            Arguments.of(
                "should update user when users userGroups are changed",
                User(
                    USER_ID,
                    null,
                    firstname = GIVEN_NAME,
                    lastname = FAMILY_NAME,
                    email = EMAIL,
                    userGroups = listOf("defaultUserGroup")
                ),
                listOf("NewUserGroup"),
                1
            ),
            Arguments.of(
                "should not update user when user details are not changed",
                User(
                    USER_ID,
                    null,
                    firstname = GIVEN_NAME,
                    lastname = FAMILY_NAME,
                    email = EMAIL,
                    userGroups = listOf("defaultUserGroup")
                ),
                listOf("defaultUserGroup"),
                0
            )
        )
    }
}

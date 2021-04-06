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
import com.gooddata.oauth2.server.common.HostBasedClientRegistrationRepositoryProperties
import com.gooddata.oauth2.server.common.Organization
import io.mockk.coEvery
import io.mockk.mockk
import org.junit.jupiter.api.Test
import org.springframework.http.HttpStatus
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.web.server.ResponseStatusException
import strikt.api.expectThat
import strikt.api.expectThrows
import strikt.assertions.isEqualTo
import strikt.assertions.isTrue
import java.lang.RuntimeException
import java.util.Optional

internal class HostBasedReactiveClientRegistrationRepositoryTest {

    private val client: AuthenticationStoreClient = mockk()

    private val repository = HostBasedReactiveClientRegistrationRepository(
        client,
        HostBasedClientRegistrationRepositoryProperties("remote", "local")
    )

    @Test
    fun `gets client registration for existing organization`() {
        coEvery { client.getOrganizationByHostname(any()) } returns Organization(
            "id",
            oauthClientId = "clientId",
            oauthClientSecret = "clientSecret",
        )

        val registration = repository.findByRegistrationId("existingId")

        expectThat(registration.blockOptional()) {
            get(Optional<ClientRegistration>::isPresent).isTrue()
            get(Optional<ClientRegistration>::get).and {
                get(ClientRegistration::getRegistrationId).isEqualTo("existingId")
                get(ClientRegistration::getProviderDetails).and {
                    get(ClientRegistration.ProviderDetails::getTokenUri)
                        .isEqualTo("local/dex/token")
                    get(ClientRegistration.ProviderDetails::getAuthorizationUri)
                        .isEqualTo("remote/dex/auth")
                }
            }
        }
    }

    @Test
    fun `finds no client registration for missing organization`() {
        coEvery { client.getOrganizationByHostname(any()) } throws ResponseStatusException(HttpStatus.NOT_FOUND)

        val registration = repository.findByRegistrationId("nonExistentId")

        expectThrows<ResponseStatusException> {
            registration.awaitOrNull()
        }
    }

    @Test
    fun `hard error is propagated`() {
        coEvery { client.getOrganizationByHostname(any()) } throws RuntimeException("error")

        val registration = repository.findByRegistrationId("nonExistentId")

        expectThrows<RuntimeException> {
            registration.awaitOrNull()
        }
    }
}

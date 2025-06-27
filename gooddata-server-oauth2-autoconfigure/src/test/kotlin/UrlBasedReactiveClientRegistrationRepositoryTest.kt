/*
 * Copyright 2025 GoodData Corporation
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

import com.gooddata.oauth2.server.IdpWebFilter.Companion.idpContextWrite
import com.gooddata.oauth2.server.OrganizationWebFilter.Companion.orgContextWrite
import io.mockk.every
import io.mockk.mockk
import java.util.Optional
import org.junit.jupiter.api.Test
import org.springframework.security.oauth2.client.registration.ClientRegistration
import reactor.core.publisher.Mono
import strikt.api.expectThat
import strikt.api.expectThrows
import strikt.assertions.isEqualTo
import strikt.assertions.isTrue

internal class UrlBasedReactiveClientRegistrationRepositoryTest {

    private val client = mockk<AuthenticationStoreClient> {
        every { getIdpById("orgId", "idpId") } returns Mono.just(
            IdentityProvider(
                "idpId",
                "https://dev-70878816.okta.com/oauth2/default",
                "clientId",
                "clientSecret",
            )
        )
    }

    private val repository = UrlBasedReactiveClientRegistrationRepository(
        CaffeineClientRegistrationCache(),
        client
    )

    @Test
    fun `gets client registration for existing organization`() {
        val organization = Organization("orgId")

        val registration = repository.findByRegistrationId("idpId")
            .orgContextWrite(organization)
            .idpContextWrite("idpId")

        expectThat(registration.blockOptional()) {
            get(Optional<ClientRegistration>::isPresent).isTrue()
            get(Optional<ClientRegistration>::get).and {
                get(ClientRegistration::getRegistrationId).isEqualTo("idpId")
                get(ClientRegistration::getProviderDetails).and {
                    get(ClientRegistration.ProviderDetails::getTokenUri)
                        .isEqualTo("https://dev-70878816.okta.com/oauth2/default/v1/token")
                    get(ClientRegistration.ProviderDetails::getAuthorizationUri)
                        .isEqualTo("https://dev-70878816.okta.com/oauth2/default/v1/authorize")
                }
            }
        }
    }

    @Test
    fun `finds no client registration for missing organization`() {
        val registration = repository.findByRegistrationId("nonExistentId")

        expectThrows<MissingOrganizationContextException> {
            registration.block()
        }
    }
}

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

import org.slf4j.LoggerFactory
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import reactor.core.publisher.Mono

/**
 * [ReactiveClientRegistrationRepository] implementation that loads [ClientRegistration] from persistent storage.
 * Client registrations are identified by request's hostname and id of the configuration.
 */
class AlternativeReactiveClientRegistrationRepository(
    private val clientRegistrationCache: ClientRegistrationCache,
    private val client: AuthenticationStoreClient
) : ReactiveClientRegistrationRepository {

    override fun findByRegistrationId(registrationId: String): Mono<ClientRegistration> =
        getOrganizationFromContext().flatMap { organization ->
            logger.info("DEBUG: 🛡️ AlternativeReactiveClientRegistrationRepository - findByRegistrationId: {}", registrationId)

            // Extract idpId from registration ID (format: "test-{idpId}")
            val idpId = if (registrationId.startsWith("test-")) {
                registrationId.removePrefix("test-")
            } else {
                // Fallback: use the registration ID as IDP ID
                registrationId
            }

            logger.info("DEBUG: 🛡️ AlternativeReactiveClientRegistrationRepository - Using IDP ID: {}", idpId)

            client.getIdpById(organization.id, idpId)
                .map { identityProvider ->
                    buildAlternativeClientRegistration(
                        registrationId = registrationId,
                        identityProvider = identityProvider,
                        clientRegistrationCache = clientRegistrationCache,
                    )
                }
        }

    companion object {
        val logger = LoggerFactory.getLogger(AlternativeReactiveClientRegistrationRepository::class.java)
    }
}

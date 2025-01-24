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

import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import reactor.core.publisher.Mono

/**
 * [ReactiveClientRegistrationRepository] implementation that loads [ClientRegistration] from persistent storage.
 * Client registrations are identified by request's hostname.
 */
class HostBasedReactiveClientRegistrationRepository(
    private val properties: HostBasedClientRegistrationRepositoryProperties,
    private val clientRegistrationCache: ClientRegistrationCache,
    private val client: AuthenticationStoreClient
) : ReactiveClientRegistrationRepository {

    override fun findByRegistrationId(registrationId: String): Mono<ClientRegistration> =
        getOrganizationFromContext().flatMap { organization ->
            client.getJitProvisioningSetting(organization.id)
                .defaultIfEmpty(JitProvisioningSetting(enabled = false))
                .map { jitProvisioningSetting ->
                    buildClientRegistration(
                        registrationId = registrationId,
                        organization = organization,
                        jitProvisioningSetting = jitProvisioningSetting,
                        properties = properties,
                        clientRegistrationCache = clientRegistrationCache,
                    )
                }
        }
}

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

import com.gooddata.oauth2.server.TestEndpointDedicatedServerAuthenticationEntryPoint.Companion.TEST_ENDPOINT_REGISTRATION_ID_PREFIX
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import reactor.core.publisher.Mono

/**
 * Composite [ReactiveClientRegistrationRepository] that routes requests to either the main
 * host-based repository or the alternative repository based on registration ID patterns.
 */
class CompositeReactiveClientRegistrationRepository(
    private val hostBasedReactiveClientRegistrationRepository: HostBasedReactiveClientRegistrationRepository,
    private val alternativeRepository: UrlBasedReactiveClientRegistrationRepository,
) : ReactiveClientRegistrationRepository {

    override fun findByRegistrationId(registrationId: String): Mono<ClientRegistration> {
        return if (registrationId.startsWith(TEST_ENDPOINT_REGISTRATION_ID_PREFIX)) {
            alternativeRepository.findByRegistrationId(registrationId)
        } else {
            hostBasedReactiveClientRegistrationRepository.findByRegistrationId(registrationId)
        }
    }
}

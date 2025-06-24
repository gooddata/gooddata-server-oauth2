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
 * Composite [ReactiveClientRegistrationRepository] that routes requests to either the main
 * host-based repository or the alternative repository based on registration ID patterns.
 */
class CompositeReactiveClientRegistrationRepository(
    private val hostBasedRepository: HostBasedReactiveClientRegistrationRepository,
    private val alternativeRepository: AlternativeReactiveClientRegistrationRepository,
) : ReactiveClientRegistrationRepository {

    override fun findByRegistrationId(registrationId: String): Mono<ClientRegistration> {
        logger.info("DEBUG: 🔄 CompositeClientRegistrationRepository - Looking up registration ID: {}", registrationId)

        // TODO: IS THERE A BETTER WAY FOR DIFFERENTIATING AMONG THE TWO AUTHENTICATION FLOWS, THAN TO RELY ON REGISTRATION ID STRUCTURE?
        return if (registrationId.startsWith("test-")) {
            logger.info("DEBUG: 🔄 CompositeClientRegistrationRepository - Using alternative repository for: {}", registrationId)
            alternativeRepository.findByRegistrationId(registrationId)
        } else {
            logger.info("DEBUG: 🔄 CompositeClientRegistrationRepository - Using host-based repository for: {}", registrationId)
            hostBasedRepository.findByRegistrationId(registrationId)
        }
    }

    companion object {
        private val logger = LoggerFactory.getLogger(CompositeReactiveClientRegistrationRepository::class.java)
    }
}

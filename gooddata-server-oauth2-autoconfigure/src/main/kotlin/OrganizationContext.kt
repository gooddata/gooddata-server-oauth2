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

import kotlinx.coroutines.reactive.awaitSingle
import org.springframework.http.HttpStatus
import org.springframework.web.server.ResponseStatusException
import reactor.core.publisher.Mono

data class OrganizationContext(var organization: Organization)

fun withOrganizationFromContext(): Mono<Organization> =
    Mono.deferContextual { contextView ->
        val organizationContext: OrganizationContext? = contextView.get(OrganizationContext::class)
        organizationContext?.let { context ->
            Mono.just(context.organization)
        } ?: Mono.empty()
    }

suspend fun getSuspendedOrganization(orgMono: Mono<Organization>): Organization =
    orgMono
        .switchIfEmpty(Mono.error(ResponseStatusException(HttpStatus.NOT_FOUND)))
        .awaitSingle()

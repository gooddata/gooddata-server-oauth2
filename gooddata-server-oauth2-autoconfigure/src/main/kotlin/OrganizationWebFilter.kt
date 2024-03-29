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

import com.gooddata.oauth2.server.OrganizationWebFilter.Companion.ORGANIZATION_CACHE_KEY
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono

/**
 * [WebFilter] that tries to get [Organization] object from metada-api by the name of the host.
 * If the organization is found, it is stored as reactor context [OrganizationContext]
 * and can be loaded within the reactor chain.
 * Else the error is logged and returned.
 */
class OrganizationWebFilter(
    private val authenticationStoreClient: AuthenticationStoreClient,
) : WebFilter {

    override fun filter(exchange: ServerWebExchange, chain: WebFilterChain): Mono<Void> {
        val hostname = exchange.request.uri.host
        return authenticationStoreClient.getOrganizationByHostname(hostname).flatMap { organization ->
            // organization is also saved to the ServerWebExchange attributes and used in blocking calls
            exchange.attributes[ORGANIZATION_CACHE_KEY] = organization
            chain.filter(exchange).orgContextWrite(organization)
        }
    }

    companion object {
        internal const val ORGANIZATION_CACHE_KEY = "organizationIdCacheKey"
        internal fun <T> Mono<T>.orgContextWrite(organization: Organization) =
            contextWrite { it.put(OrganizationContext::class, OrganizationContext(organization)) }
    }
}

/**
 * The [OrganizationContext] is a context to store [Organization] loaded from metadata-api
 * and stored as context in [OrganizationWebFilter]
 */
data class OrganizationContext(var organization: Organization)

class MissingOrganizationContextException : IllegalStateException(
    "There's no Organization instance located either in ReactorContext or in ServerWebExchange attributes. " +
        "Please check if OrganizationWebFilter is configured properly"
)

/**
 * Helper method to get [Mono] of [Organization] from the reactor context.
 * If the reactor context does not contain [OrganizationContext] represented by key OrganizationContext::class,
 * the [MissingOrganizationContextException] is return as [Mono.error].
 * Else the [OrganizationContext] is gotten from the reactor context
 * and [Organization] is extracted from the [OrganizationContext] and returned as [Mono]
 */
fun getOrganizationFromContext(): Mono<Organization> = Mono.deferContextual { contextView ->
    if (!contextView.hasKey(OrganizationContext::class)) {
        Mono.error(MissingOrganizationContextException())
    } else {
        Mono.just(contextView.get<OrganizationContext>(OrganizationContext::class).organization)
    }
}

fun ServerWebExchange.getOrganizationFromAttributes(): Organization =
    when (val organization = attributes[ORGANIZATION_CACHE_KEY]) {
        is Organization -> organization
        else -> throw MissingOrganizationContextException()
    }

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

import io.mockk.every
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

internal fun mockOrganization(client: AuthenticationStoreClient, host: String, organization: Organization) {
    every { client.getOrganizationByHostname(host) } returns Mono.just(organization)
}

internal fun mockOrganizationSettings(client: AuthenticationStoreClient, organizationId: String) {
    every { client.getJitProvisioningSetting(organizationId) } returns Mono.empty()
}

internal fun mockOrganizationError(client: AuthenticationStoreClient, host: String, exception: Throwable) {
    every { client.getOrganizationByHostname(host) } returns Mono.error(exception)
}

internal fun mockUserById(
    client: AuthenticationStoreClient,
    organizationId: String,
    id: String,
    user: User = User(id)
) {
    every { client.getUserById(organizationId, id) } returns Mono.just(user)
}

internal fun mockUserByAuthId(
    client: AuthenticationStoreClient,
    organizationId: String,
    authenticationId: String,
    user: User?
) {
    every { client.getUserByAuthenticationId(organizationId, authenticationId) } returns if (user != null) {
        Mono.just(user)
    } else {
        Mono.empty()
    }
}

internal fun mockCookieSecurityProperties(
    client: AuthenticationStoreClient,
    organizationId: String,
    cookieProperties: CookieSecurityProperties
) {
    every { client.getCookieSecurityProperties(organizationId) } returns Mono.just(cookieProperties)
}

// Using block() is not recommended but related code should be removed soon, so we probably don't need to fix it now.
fun CookieSerializer.encodeCookieBlocking(exchange: ServerWebExchange, internalCookie: String) =
    encodeCookie(exchange, internalCookie).block()

fun CookieSerializer.decodeCookieBlocking(exchange: ServerWebExchange, externalCookie: String) =
    decodeCookie(exchange, externalCookie).block()

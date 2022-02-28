/*
 * Copyright 2022 GoodData Corporation
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

import com.gooddata.oauth2.server.common.JwkException
import com.nimbusds.jose.jwk.JWKSet
import org.springframework.web.reactive.function.client.WebClient
import reactor.core.publisher.Mono
import java.text.ParseException

/**
 * JWK source which retrieves JWK set from given URL. It's simplified
 * [org.springframework.security.oauth2.jwt.ReactiveRemoteJWKSource] with no caching.
 * @param[webClient] WEB client used for requests
 * @param[jwkSetURL] URL where to retrieve JWK set from
 * @see org.springframework.security.oauth2.jwt.ReactiveRemoteJWKSource
 */
class SimpleReactiveRemoteJWKSource(
    private val webClient: WebClient = WebClient.create(),
    private val jwkSetURL: String
) {

    /**
     * Retrieves JWK set.
     * @return The updated JWK set.
     * @throws RemoteKeySourceException If JWK retrieval failed.
     */
    fun getJwkSet(): Mono<JWKSet> {
        return webClient.get()
            .uri(jwkSetURL)
            .retrieve()
            .bodyToMono(String::class.java)
            .map { body -> parse(body) }
    }

    private fun parse(body: String): JWKSet {
        return try {
            JWKSet.parse(body)
        } catch (e: ParseException) {
            throw JwkException("Unable to parse JWK set from response body: '${e.message}'", e)
        }
    }
}

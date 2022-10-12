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
package com.gooddata.oauth2.server

import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.util.Resource
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.RequestEntity
import org.springframework.web.client.RestOperations
import org.springframework.web.client.RestTemplate
import java.net.URL

/**
 * Rewritten and simplified [com.nimbusds.jose.jwk.source.RemoteJWKSet] with external caching.
 * @param[restOperations] REST operations (template)
 * @param[jwkSetUri] JWK set URI
 * @param[jwkCache] JWK cache
 */
class SimpleRemoteJwkSource(
    private val restOperations: RestOperations = RestTemplate(),
    private val jwkSetUri: String,
    private val jwkCache: JwkCache
) : JWKSource<SecurityContext> {

    override fun get(jwkSelector: JWKSelector?, context: SecurityContext?) = jwkSelector?.select(get()) ?: emptyList()

    fun get() = jwkCache.get(jwkSetUri) { JWKSet.parse(retrieveResource(URL(jwkSetUri)).content) }
        ?: throw JwkException("Unable to retrieve JWKs from '$jwkSetUri'.")

    private fun retrieveResource(url: URL): Resource {
        val headers = HttpHeaders().apply {
            accept = listOf(
                MediaType.APPLICATION_JSON,
                MediaType.valueOf(JWKSet.MIME_TYPE)
            )
        }

        val response = getResponse(url, headers)

        return when (response.statusCode) {
            HttpStatus.OK -> Resource(response.body, "UTF-8")
            else -> throw JwkException(response.toString())
        }
    }

    @Suppress("TooGenericExceptionCaught")
    private fun getResponse(url: URL, headers: HttpHeaders) =
        try {
            val request = RequestEntity<Void>(headers, HttpMethod.GET, url.toURI())
            restOperations.exchange(request, String::class.java)
        } catch (e: Throwable) {
            throw JwkException("Unable to retrieve JWKs", e)
        }
}

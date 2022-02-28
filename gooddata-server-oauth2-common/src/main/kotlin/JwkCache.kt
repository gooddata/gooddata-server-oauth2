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

package com.gooddata.oauth2.server.common

import com.github.benmanes.caffeine.cache.Cache
import com.github.benmanes.caffeine.cache.Caffeine
import com.nimbusds.jose.jwk.JWKSet
import java.util.concurrent.TimeUnit

/**
 * Stores JWKs.
 */
interface JwkCache {

    /**
     * Retrieve JWK set for given URI.
     * @param setUri URI
     * @param create creates/retrieves JWK set. Its called when no JWK set is found in cache.
     */
    fun get(setUri: String, create: () -> JWKSet?): JWKSet?
}

/**
 * Caffeine implementation of JWK cache.
 * @param maxSize max cache size. Default is [CACHE_MAX_SIZE].
 * @param expireAfterWriteMinutes cached values are expired after write after this value in minutes. Default is
 * [CACHE_EXPIRE_AFTER_WRITE_MINUTES].
 */
class CaffeineJwkCache(
    maxSize: Long = CACHE_MAX_SIZE,
    expireAfterWriteMinutes: Long = CACHE_EXPIRE_AFTER_WRITE_MINUTES
) : JwkCache {

    private val cache: Cache<String, JWKSet>

    init {
        val caffeine = Caffeine.newBuilder()
            .maximumSize(maxSize)
            .expireAfterWrite(expireAfterWriteMinutes, TimeUnit.MINUTES)
        cache = caffeine.build()
    }

    override fun get(setUri: String, create: () -> JWKSet?): JWKSet = cache.get(setUri) { create() }

    companion object {
        const val CACHE_MAX_SIZE: Long = 10_000
        const val CACHE_EXPIRE_AFTER_WRITE_MINUTES: Long = 60
    }
}

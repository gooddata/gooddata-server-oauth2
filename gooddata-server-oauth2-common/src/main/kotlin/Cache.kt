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

import com.github.benmanes.caffeine.cache.Caffeine
import java.util.concurrent.TimeUnit

/**
 * Retrieve cached value for given key.
 * @param[K] caching key
 * @param[V] cached value
 */
interface Cache<K, V> {

    /**
     * Retrieve value for given k.
     * @param key key
     * @param create creates/retrieves value. Its called when no value is found in cache.
     */
    fun get(key: K, create: () -> V): V
}

/**
 * Caffeine implementation of cache.
 * @param[K] caching key
 * @param[V] cached value
 * @param[maxSize] max cache size. Default is [CACHE_MAX_SIZE].
 * @param[expireAfterWriteMinutes] cached values are expired after write after this value in minutes. Default is
 * [CACHE_EXPIRE_AFTER_WRITE_MINUTES].
 */
abstract class CaffeineCache<K, V>(
    maxSize: Long = CACHE_MAX_SIZE,
    expireAfterWriteMinutes: Long = CACHE_EXPIRE_AFTER_WRITE_MINUTES
) : Cache<K, V> {

    private val cache: com.github.benmanes.caffeine.cache.Cache<K, V>

    init {
        val caffeine = Caffeine.newBuilder()
            .maximumSize(maxSize)
            .expireAfterWrite(expireAfterWriteMinutes, TimeUnit.MINUTES)
        cache = caffeine.build()
    }

    override fun get(key: K, create: () -> V): V = cache.get(key) { create() }

    companion object {
        const val CACHE_MAX_SIZE: Long = 10_000
        const val CACHE_EXPIRE_AFTER_WRITE_MINUTES: Long = 60
    }
}

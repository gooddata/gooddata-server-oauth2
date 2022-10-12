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

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.ConstructorBinding
import org.springframework.boot.context.properties.bind.DefaultValue

/**
 * Caching properties.
 * @param[jwkMaxSize] max size of JWK cache
 * @param[jwkExpireAfterWriteMinutes] time in minutes after write after which is value expired in JWK cache
 * @see com.gooddata.oauth2.server.JwkCache
 */
@ConstructorBinding
@ConfigurationProperties(prefix = "spring.security.oauth2.client.cache")
class CachingProperties(

    @DefaultValue("${CaffeineCache.CACHE_MAX_SIZE}")
    val jwkMaxSize: Long,

    @DefaultValue("${CaffeineCache.CACHE_EXPIRE_AFTER_WRITE_MINUTES}")
    val jwkExpireAfterWriteMinutes: Long,

    @DefaultValue("${CaffeineCache.CACHE_MAX_SIZE}")
    val clientRegistrationMaxSize: Long,

    @DefaultValue("${CaffeineCache.CACHE_EXPIRE_AFTER_WRITE_MINUTES}")
    val clientRegistrationExpireAfterWriteMinutes: Long
)

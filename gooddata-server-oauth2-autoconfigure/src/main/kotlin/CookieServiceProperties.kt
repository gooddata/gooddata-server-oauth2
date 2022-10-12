/*
 * Copyright 2021 GoodData Corporation
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

import io.netty.handler.codec.http.cookie.CookieHeaderNames
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.ConstructorBinding
import org.springframework.boot.context.properties.bind.DefaultValue
import java.time.Duration
import java.time.Instant

@ConstructorBinding
@ConfigurationProperties(prefix = "spring.security.oauth2.client.cookies")
class CookieServiceProperties(
    /**
     * Defines cookie validity.
     */
    @DefaultValue("7d")
    val duration: Duration,

    /**
     * Defines which SameSite attribute is used for created cookies.
     */
    @DefaultValue("Lax")
    val sameSite: CookieHeaderNames.SameSite,

    /**
     * Max lifetime of keySet cache. This value is used when doing manual emergency keySet rotation (to remove all
     * past decryption keys). This is maximal time, when manually rotated keys will be still used.
     */
    @DefaultValue("10m")
    val keySetCacheDuration: Duration,
) {
    fun validTo(now: Instant): Instant = now + keySetCacheDuration
}

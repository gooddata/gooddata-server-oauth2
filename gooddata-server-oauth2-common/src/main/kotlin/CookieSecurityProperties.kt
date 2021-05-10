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
package com.gooddata.oauth2.server.common

import com.google.crypto.tink.KeysetHandle
import java.time.Instant
import java.time.Duration

/**
 * CookieSecurityProperties - stores information about Cookies security.
 */

data class CookieSecurityProperties(
    /**
     * Contains [KeysetHandle], which is used to encrypting and decrypting cookies.
     */
    val keySet: KeysetHandle,
    /**
     * Time of last rotation on encryption key in [keySet]
     */
    val lastRotation: Instant,
    /**
     * Configured interval between rotations of encryption key [keySet]
     */
    val rotationInterval: Duration,
)

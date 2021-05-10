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

import com.google.crypto.tink.Aead
import com.google.crypto.tink.aead.AeadConfig
import kotlinx.coroutines.runBlocking
import java.security.GeneralSecurityException
import java.time.Instant
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap

/**
 * Class for converting internal string serialization of cookie to external string serialization and back.
 * It currently does two things:
 * * encrypt value with Authenticated Encryption to improve security
 * * encodes with base64, so it is safe to store value in header
 */
class CookieSerializer(
    private val cookieServiceProperties: CookieServiceProperties,
    private val client: AuthenticationStoreClient,
) {
    data class AeadCache(
        val aead: Aead,
        val validTo: Instant,
    )

    val aeadCache = ConcurrentHashMap<String, AeadCache>()

    init {
        AeadConfig.register()
    }

    /**
     * Get [Aead] from cache (if still valid) or from [AuthenticationStoreClient].
     */
    private fun getAead(hostname: String): Aead {
        val aead = aeadCache[hostname]

        return if (aead == null || aead.validTo.isBefore(Instant.now())) {
            synchronized(aeadCache) {
                val synchronizedAead = aeadCache[hostname]
                if (synchronizedAead == null || synchronizedAead.validTo.isBefore(Instant.now())) {
                    val newProperties = runBlocking {
                        val organization = client.getOrganizationByHostname(hostname)
                        client.getCookieSecurityProperties(organization.id)
                    }
                    val propertiesValidity = newProperties.lastRotation.plus(newProperties.rotationInterval)
                    val cacheValidity = Instant.now().plus(cookieServiceProperties.keySetCacheDuration)
                    val validity = if (propertiesValidity.isBefore(cacheValidity)) {
                        propertiesValidity
                    } else {
                        cacheValidity
                    }
                    val newAead = AeadCache(
                        newProperties.keySet.getPrimitive(Aead::class.java),
                        validity
                    )
                    aeadCache[hostname] = newAead
                    newAead.aead
                } else {
                    synchronizedAead.aead
                }
            }
        } else {
            aead.aead
        }
    }

    /**
     * Convert cookie from internal string serialization to external string serialization.
     */
    fun encodeCookie(hostname: String, internalCookie: String): String {
        val aead = getAead(hostname)
        val encryptedCookie = aead.encrypt(internalCookie.toByteArray(), null)
        return String(Base64.getEncoder().encode(encryptedCookie))
    }

    /**
     * Convert cookie from external string serialization to internal string serialization.
     * If cookie is malformed or can not be authenticated, than it throws 'IllegalArgumentException'.
     *
     * @throws IllegalArgumentException when decryption fails
     */
    fun decodeCookie(hostname: String, externalCookie: String): String {
        val encryptedCookie = Base64.getDecoder().decode(externalCookie.toByteArray())
        val aead = getAead(hostname)
        val internalCookie = try {
            aead.decrypt(encryptedCookie, null)
        } catch (_: GeneralSecurityException) {
            throw IllegalArgumentException("Decrypt failed")
        }
        return String(internalCookie)
    }
}

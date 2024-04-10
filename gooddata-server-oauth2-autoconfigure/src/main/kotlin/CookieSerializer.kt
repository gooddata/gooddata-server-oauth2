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

import com.google.crypto.tink.Aead
import com.google.crypto.tink.aead.AeadConfig
import org.springframework.web.server.ServerWebExchange
import java.security.GeneralSecurityException
import java.time.Instant
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap

private typealias Hostname = String

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
    private data class AeadWithExpiration(
        val aead: Aead,
        val validTo: Instant,
    ) {
        fun getValidAead(now: Instant): Aead? = aead.takeIf { isValid(now) }

        private fun isValid(now: Instant) = validTo > now
    }

    private val aeadCache = ConcurrentHashMap<Hostname, AeadWithExpiration>()

    init {
        AeadConfig.register()
    }

    /**
     * Convert cookie from internal string serialization to external string serialization.
     */
    fun encodeCookie(exchange: ServerWebExchange, internalCookie: String): String {
        val aead = getAead(exchange)
        val encryptedCookie = aead.encrypt(internalCookie.toByteArray(), null)
        return encryptedCookie.toBase64()
    }

    /**
     * Convert cookie from external string serialization to internal string serialization.
     * If cookie is malformed or can not be authenticated, then it throws 'IllegalArgumentException'.
     *
     * @throws IllegalArgumentException when decryption fails
     */
    fun decodeCookie(exchange: ServerWebExchange, externalCookie: String): String {
        val aead = getAead(exchange)
        val encryptedCookie = externalCookie.fromBase64()
        val internalCookie = try {
            aead.decrypt(encryptedCookie, null)
        } catch (_: GeneralSecurityException) {
            throw IllegalArgumentException("Decrypt failed")
        }
        return String(internalCookie)
    }

    /**
     * Get [Aead] from cache (if still valid) or from [AuthenticationStoreClient].
     */
    private fun getAead(exchange: ServerWebExchange): Aead {
        val now = Instant.now()
        return getAeadFromCache(exchange, now) ?: resolveAndCacheAead(exchange, now)
    }

    private fun getAeadFromCache(exchange: ServerWebExchange, now: Instant): Aead? =
        aeadCache[exchange.request.uri.host]?.let { aead -> aead.getValidAead(now) }

    private fun resolveAndCacheAead(exchange: ServerWebExchange, now: Instant): Aead {
        // process before compute() method for not blocking cache
        val cookieSecurityProperties = readCookieSecurityProperties(exchange)
        return aeadCache.compute(exchange.request.uri.host) { _, _ ->
            AeadWithExpiration(
                aead = cookieSecurityProperties.keySet.getPrimitive(Aead::class.java),
                validTo = minOf(cookieSecurityProperties.validTo, cookieServiceProperties.validTo(now))
            )
        }!!.aead
    }

    private fun readCookieSecurityProperties(exchange: ServerWebExchange): CookieSecurityProperties =
        client.getCookieSecurityProperties(exchange.getOrganizationFromAttributes().id).block()
            ?: throw IllegalArgumentException("Cookie security properties not found.")

    private fun ByteArray.toBase64(): String = String(Base64.getEncoder().encode(this))

    private fun String.fromBase64(): ByteArray = Base64.getDecoder().decode(this.toByteArray())
}

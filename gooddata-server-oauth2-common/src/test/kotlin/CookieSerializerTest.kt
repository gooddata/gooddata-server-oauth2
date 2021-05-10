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

import com.google.crypto.tink.CleartextKeysetHandle
import com.google.crypto.tink.JsonKeysetReader
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.netty.handler.codec.http.cookie.CookieHeaderNames
import org.intellij.lang.annotations.Language
import org.junit.jupiter.api.Test
import strikt.api.expectCatching
import strikt.api.expectThat
import strikt.api.expectThrows
import strikt.assertions.isEqualTo
import strikt.assertions.isGreaterThan
import strikt.assertions.isLessThan
import strikt.assertions.isSuccess
import java.time.Duration
import java.time.Instant
import java.util.Base64

internal class CookieSerializerTest {
    @Language("JSON")
    private val keyset = """
        {
            "primaryKeyId": 482808123,
            "key": [
                {
                    "keyData": {
                        "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
                        "keyMaterialType": "SYMMETRIC",
                        "value": "GiBpR+IuA4xWtq5ZijTXae/Y9plMy0TMMc97wqdOrK7ndA=="
                    },
                    "outputPrefixType": "TINK",
                    "keyId": 482808123,
                    "status": "ENABLED"
                }
            ]
        }
    """

    private val client: AuthenticationStoreClient = mockk {
        coEvery { getOrganizationByHostname("localhost") } returns Organization("org")
        coEvery { getCookieSecurityProperties("org") } returns CookieSecurityProperties(
            keySet = CleartextKeysetHandle.read(JsonKeysetReader.withBytes(keyset.toByteArray())),
            lastRotation = Instant.now(),
            rotationInterval = Duration.ofDays(1),
        )
    }

    private val properties = CookieServiceProperties(
        Duration.ofDays(1),
        CookieHeaderNames.SameSite.Lax,
        Duration.ofDays(1)
    )
    private val cookieSerializer = CookieSerializer(properties, client)

    @Test
    fun `output is base64 encoded`() {
        val encoded = cookieSerializer.encodeCookie(
            "localhost",
            arrayOf<Byte>(0, 1, 2, 3, 4, 20, 21, 50, 80, 127, -128, -127, -5, -1).toString()
        )
        expectCatching {
            Base64.getDecoder().decode(encoded.toByteArray())
        }.isSuccess()
    }

    @Test
    fun `invalid base64 value throws error`() {
        val invalidValue = "not a base 64 value !@#$%^&*()_+"
        expectThrows<IllegalArgumentException> {
            cookieSerializer.decodeCookie("localhost", invalidValue)
        }
    }

    @Test
    fun `invalid encrypted value throws error`() {
        val invalidValue = String(Base64.getEncoder().encode("some not-correctly-encrypted value".toByteArray()))
        expectThrows<IllegalArgumentException> {
            cookieSerializer.decodeCookie("localhost", invalidValue)
        }
    }

    @Test
    fun `output is encrypted`() {
        /**
         * Size of input to test - bigger the value, more reliable test
         */
        val inputSize = 65536
        /**
         * Heuristic parameter - increase in case of flapping test
         */
        val acceptedErrorInPercents = 50.0

        val input = ByteArray(inputSize) { 0 }
        val encoded = cookieSerializer.encodeCookie("localhost", String(input))
        val encrypted = Base64.getDecoder().decode(encoded.toByteArray())
        val byteSize = Byte.MAX_VALUE - Byte.MIN_VALUE + 1
        val frequencyTable = IntArray(byteSize) { 0 }

        encrypted.forEach {
            frequencyTable[it.toInt() - Byte.MIN_VALUE]++
        }

        /**
         * It is not exactly possible to test, if input is encrypted.
         * We perform only frequency analysis as basic heuristic for testing if encryption is present.
         */
        val idealFrequency = (inputSize / byteSize).toDouble()
        val minAcceptedFrequency = (idealFrequency * (1.0 - acceptedErrorInPercents / 100.0)).toInt()
        val maxAcceptedFrequency = (idealFrequency * (1.0 + acceptedErrorInPercents / 100.0)).toInt()
        for (byte in 0 until byteSize) {
            expectThat(frequencyTable[byte]).isGreaterThan(minAcceptedFrequency)
            expectThat(frequencyTable[byte]).isLessThan(maxAcceptedFrequency)
        }
    }

    @Test
    fun `is possible to decrypt encrypted value`() {
        val input = "testingValue"
        val transformed = cookieSerializer.decodeCookie("localhost", cookieSerializer.encodeCookie("localhost", input))
        expectThat(transformed).isEqualTo(input)
    }

    @Test
    fun `getAead scenarios with large TTL`() {
        mockkStatic(Instant::class)

        val client: AuthenticationStoreClient = mockk {
            coEvery { getOrganizationByHostname("localhost") } returns Organization("org")
            coEvery { getCookieSecurityProperties("org") } answers {
                CookieSecurityProperties(
                    keySet = CleartextKeysetHandle.read(JsonKeysetReader.withBytes(keyset.toByteArray())),
                    lastRotation = Instant.now(),
                    rotationInterval = Duration.ofSeconds(10),
                )
            }
        }

        val properties = CookieServiceProperties(
            Duration.ofDays(1),
            CookieHeaderNames.SameSite.Lax,
            Duration.ofSeconds(50)
        )

        val cookieSerializer = CookieSerializer(properties, client)

        // Start at time 0
        every { Instant.now() } returns Instant.ofEpochSecond(0)

        // Called with no cache - read from backend
        cookieSerializer.encodeCookie("localhost", "")
        coVerify(exactly = 1) { client.getCookieSecurityProperties("org") }

        // Called before rotationInterval and before TTL - use cache
        every { Instant.now() } returns Instant.ofEpochSecond(9)
        cookieSerializer.encodeCookie("localhost", "")
        coVerify(exactly = 1) { client.getCookieSecurityProperties("org") }

        // Call after rotationInterval and before TTL - read from backend
        every { Instant.now() } returns Instant.ofEpochSecond(11)
        cookieSerializer.encodeCookie("localhost", "")
        coVerify(exactly = 2) { client.getCookieSecurityProperties("org") }
    }

    @Test
    fun `getAead scenarios with small TTL`() {
        mockkStatic(Instant::class)

        val client: AuthenticationStoreClient = mockk {
            coEvery { getOrganizationByHostname("localhost") } returns Organization("org")
            coEvery { getCookieSecurityProperties("org") } answers {
                CookieSecurityProperties(
                    keySet = CleartextKeysetHandle.read(JsonKeysetReader.withBytes(keyset.toByteArray())),
                    lastRotation = Instant.now(),
                    rotationInterval = Duration.ofSeconds(10),
                )
            }
        }

        val properties = CookieServiceProperties(
            Duration.ofDays(1),
            CookieHeaderNames.SameSite.Lax,
            Duration.ofSeconds(5)
        )

        val cookieSerializer = CookieSerializer(properties, client)

        // Start at time 0
        every { Instant.now() } returns Instant.ofEpochSecond(0)

        // Called with no cache - read from backend
        cookieSerializer.encodeCookie("localhost", "")
        coVerify(exactly = 1) { client.getCookieSecurityProperties("org") }

        // Called before rotationInterval and after TTL - read from backend
        every { Instant.now() } returns Instant.ofEpochSecond(9)
        cookieSerializer.encodeCookie("localhost", "")
        coVerify(exactly = 2) { client.getCookieSecurityProperties("org") }

        // Call after rotationInterval and after TTL - read from backend
        every { Instant.now() } returns Instant.ofEpochSecond(20)
        cookieSerializer.encodeCookie("localhost", "")
        coVerify(exactly = 3) { client.getCookieSecurityProperties("org") }
    }
}

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

import io.netty.handler.codec.http.cookie.CookieHeaderNames
import org.junit.jupiter.api.Test
import strikt.api.expectCatching
import strikt.api.expectThat
import strikt.api.expectThrows
import strikt.assertions.isEqualTo
import strikt.assertions.isGreaterThan
import strikt.assertions.isLessThan
import strikt.assertions.isSuccess
import java.time.Duration
import java.util.Base64

internal class CookieSerializerTest {
    private val properties = CookieServiceProperties(Duration.ofDays(1), CookieHeaderNames.SameSite.Lax, "")

    private val cookieSerializer = CookieSerializer(properties)

    @Test
    fun `output is base64 encoded`() {
        val encoded = cookieSerializer.encodeCookie(
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
            cookieSerializer.decodeCookie(invalidValue)
        }
    }

    @Test
    fun `invalid encrypted value throws error`() {
        val invalidValue = String(Base64.getEncoder().encode("some not-correctly-encrypted value".toByteArray()))
        expectThrows<IllegalArgumentException> {
            cookieSerializer.decodeCookie(invalidValue)
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
        val encoded = cookieSerializer.encodeCookie(String(input))
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
        val transformed = cookieSerializer.decodeCookie(cookieSerializer.encodeCookie(input))
        expectThat(transformed).isEqualTo(input)
    }
}

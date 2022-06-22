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

import com.fasterxml.jackson.databind.ObjectMapper
import org.intellij.lang.annotations.Language
import org.junit.jupiter.api.Test
import strikt.api.expectThat
import strikt.assertions.isEqualTo

class KotlinLoggingTest {
    @Test
    fun `format token for logging`() {
        @Language("JSON")
        val jsonToken = """
        {
            "ver": 1,
            "jti": "AT.1ZXB7q6_TJstYdlWVt7WYn5T4SLT_soscx1TfOig68I",
            "iss": "https://dev-1234567.okta.com",
            "aud": "https://dev-1234567.okta.com",
            "sub": "developer@gooddata.com",
            "iat": 1655214008,
            "exp": 1655217608,
            "cid": "0oa58bfjXc7GAFuON5d7",
            "uid": "00u58ateRTP95KWw75d7",
            "scp":
            [
                "openid",
                "profile"
            ],
            "auth_time": 1655210187
        }
        """

        val safeJsonToken = """
        {
            "ver": 1,
            "jti": "AT.1ZXB7q6_TJstYdlWVt7WYn5T4SLT_soscx1Tf***",
            "iss": "https://dev-1234567.okta.com",
            "aud": "https://dev-1234567.okta.com",
            "sub": "developer@gooddata.com",
            "iat": "2022-06-14 13:40:08",
            "exp": "2022-06-14 14:40:08",
            "cid": "0oa58bfjXc7GAF***",
            "uid": "00u58ateRTP95K***",
            "scp":
            [
                "openid",
                "profile"
            ],
            "auth_time": "2022-06-14 12:36:27"
        }
        """

        expectThat(
            formatJsonForLogging(jsonToken)
        ).isEqualTo(safeJsonToken.normalize())
    }

    @Test
    fun `replaceLast`() {
        expectThat(replaceLast("1234567890", 5, "**")).isEqualTo("12345**")
        expectThat(replaceLast("", 5, "**")).isEqualTo("**")
    }

    @Test
    fun `seconds to DatTime string`() {
        expectThat(
            secondsToDateTimeString(1655797391)
        ).isEqualTo("2022-06-21 07:43:11")
    }

    private fun String.normalize(): String = ObjectMapper().readTree(this).toString()
}

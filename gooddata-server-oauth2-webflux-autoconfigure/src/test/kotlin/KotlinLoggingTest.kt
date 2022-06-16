package com.gooddata.oauth2.server.reactive

import com.fasterxml.jackson.databind.ObjectMapper
import org.intellij.lang.annotations.Language
import org.junit.jupiter.api.Test
import strikt.api.expectThat
import strikt.assertions.isEqualTo

class KotlinLoggingTest {
    @Test
    fun `mask sensitive values in token`() {
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
            "iat": 1655214008,
            "exp": 1655217608,
            "cid": "0oa58bfjXc7GAF***",
            "uid": "00u58ateRTP95K***",
            "scp":
            [
                "openid",
                "profile"
            ],
            "auth_time": 1655210187
        }
        """

        expectThat(
            maskSensitiveValues(jsonToken)
        ).isEqualTo(safeJsonToken.normalize())
    }

    private fun String.normalize(): String = ObjectMapper().readTree(this).toString()
}

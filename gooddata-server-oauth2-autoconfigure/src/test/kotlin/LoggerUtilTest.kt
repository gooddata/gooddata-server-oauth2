/*
 * Copyright 2023 GoodData Corporation
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

import com.gooddata.oauth2.server.LogKey.ACTION
import com.gooddata.oauth2.server.LogKey.EXCEPTION
import com.gooddata.oauth2.server.LogKey.STATE
import com.gooddata.oauth2.server.LogKey.USER_ID
import io.mockk.every
import io.mockk.mockk
import io.netty.handler.logging.LogLevel
import io.netty.handler.logging.LogLevel.ERROR
import org.junit.jupiter.api.Test
import org.slf4j.Logger
import strikt.api.expectThat
import strikt.assertions.isEqualTo
import java.lang.IllegalArgumentException

class LoggerUtilTest {
    @Test
    fun `logInfo test`() {
        mockk<Logger> {
            every { isInfoEnabled } returns true
        }
        val logBuilder = LogBuilder(LogLevel.INFO)
        logBuilder.run {
            withMessage { "some message" }
            withAction("theAction")
            withUserId("demoUser")
            withState("started")
        }

        val params = arrayOf<Any>(
            ACTION.keyName,
            "theAction",
            STATE.keyName,
            "started",
            USER_ID.keyName,
            "demoUser",
        )
        expectThat(logBuilder.paramsToArray()).isEqualTo(params)
    }

    @Test
    fun `logError test`() {
        mockk<Logger> {
            every { isErrorEnabled } returns true
        }
        val exception = IllegalArgumentException("wrong argument")
        val logBuilder = LogBuilder(ERROR)
        logBuilder.run {
            withMessage { "some message" }
            withAction("theAction")
            withException(exception)
        }

        val params = arrayOf<Any>(
            ACTION.keyName,
            "theAction",
            EXCEPTION.keyName,
            exception,
        )
        expectThat(logBuilder.paramsToArray()).isEqualTo(params)
    }
}

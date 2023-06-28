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
import io.netty.handler.logging.LogLevel
import io.netty.handler.logging.LogLevel.DEBUG
import io.netty.handler.logging.LogLevel.ERROR
import io.netty.handler.logging.LogLevel.INFO
import io.netty.handler.logging.LogLevel.TRACE
import io.netty.handler.logging.LogLevel.WARN
import mu.KLogger
import org.slf4j.Logger
import org.slf4j.Marker
import org.slf4j.MarkerFactory

val GD_API_MARKER: Marker = MarkerFactory.getMarker("GD_STRUCT_LOG")

fun KLogger.logInfo(block: LogBuilder.() -> Unit) {
    if (isInfoEnabled) {
        log(this, block, INFO)
    }
}

fun KLogger.logError(exception: Throwable, block: LogBuilder.() -> Unit) {
    if (isErrorEnabled) {
        log(this, block, ERROR, exception)
    }
}

private fun log(logger: Logger, block: LogBuilder.() -> Unit, logLevel: LogLevel) {
    LogBuilder(logLevel)
        .apply(block)
        .writeTo(logger)
}

private fun log(logger: Logger, block: LogBuilder.() -> Unit, logLevel: LogLevel, exception: Throwable) {
    LogBuilder(logLevel)
        .apply { withException(exception) }
        .apply(block)
        .writeTo(logger)
}

class LogBuilder internal constructor(val logLevel: LogLevel) {
    private val params = mutableMapOf<LogKey, Any>()
    private var message: () -> String = { "" }
    private var exception: Throwable? = null

    fun withMessage(message: () -> String) {
        this.message = message
    }

    fun withException(t: Throwable) {
        exception = t
    }

    fun withAction(action: String) {
        params[ACTION] = action
    }

    fun withState(state: String) {
        params[STATE] = state
    }

    fun withUserId(userId: String) {
        params[USER_ID] = userId
    }

    internal fun writeTo(logger: Logger) {
        log(logger, logLevel, message(), paramsToArray())
    }

    internal fun paramsToArray(): Array<Any> {
        exception?.let { params[EXCEPTION] = it }
        return params.toSortedMap(compareBy { it.ordinal })
            .flatMap { listOf(it.key.keyName, it.value) }
            .toTypedArray()
    }

    @Suppress("SpreadOperator")
    fun log(logger: Logger, logLevel: LogLevel, message: String, params: Array<Any>) = when (logLevel) {
        DEBUG -> logger.debug(GD_API_MARKER, message, *params)
        ERROR -> logger.error(GD_API_MARKER, message, *params)
        INFO -> logger.info(GD_API_MARKER, message, *params)
        TRACE -> logger.trace(GD_API_MARKER, message, *params)
        WARN -> logger.warn(GD_API_MARKER, message, *params)
    }
}

enum class LogKey(val keyName: String) {
    ACTION("action"),
    EXCEPTION("exc"),
    STATE("state"),
    USER_ID("userId"),
}

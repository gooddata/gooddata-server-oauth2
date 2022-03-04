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
package com.gooddata.oauth2.server.servlet

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.springframework.http.HttpHeaders
import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import java.net.URLDecoder

/**
 * Handles the authentications failure
 */
class OAuth2FailureHandler : AuthenticationFailureHandler {

    override fun onAuthenticationFailure(
        request: HttpServletRequest,
        response: HttpServletResponse,
        exception: AuthenticationException
    ) {
        response.status = HttpServletResponse.SC_UNAUTHORIZED
        response.addHeader(
            HttpHeaders.WWW_AUTHENTICATE,
            "Unable to authenticate: ${request.getRequestErrorCode()}: ${request.getRequestErrorDescription()}"
        )
    }

    private fun HttpServletRequest.queryParams() = queryString.split("&").associate {
        val (param, paramValue) = it.split("=")
        param to URLDecoder.decode(paramValue, Charsets.UTF_8)
    }

    private fun HttpServletRequest.getQueryParam(paramName: String) = queryParams()[paramName]

    private fun HttpServletRequest.getRequestErrorCode(): String =
        getQueryParam(OAuth2ParameterNames.ERROR) ?: OAuth2ParameterNames.ERROR

    private fun HttpServletRequest.getRequestErrorDescription(): String =
        getQueryParam(OAuth2ParameterNames.ERROR_DESCRIPTION) ?: DEFAULT_ERROR_DESCRIPTION

    companion object {
        private const val DEFAULT_ERROR_DESCRIPTION = "Authentication failed"
    }
}

/*
 * Copyright 2022 GoodData Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License a
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

import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler
import reactor.core.publisher.Mono

/**
 * Handles the authentications failure
 */
class ServerOAuth2FailureHandler(
    private val auditClient: AuthenticationAuditClient
) : ServerAuthenticationFailureHandler {

    override fun onAuthenticationFailure(exchange: WebFilterExchange, exception: AuthenticationException): Mono<Void> {
        val errorDescription = exchange.getRequestErrorDescription()
            ?: exception.message?.nullIfBlank()?.removeIllegalCharacters()
            ?: DEFAULT_ERROR_DESCRIPTION
        val errorCode = exchange.getRequestErrorCode()

        return getOrganizationFromContext().flatMap { organization ->
            val sourceIp = exchange.exchange.request.remoteAddress?.address?.hostAddress
            auditClient.recordLoginFailure(
                orgId = organization.id,
                userId = "",
                source = sourceIp,
                sessionContextType = AuthMethod.OIDC,
                sessionContextIdentifier = null,
                errorCode = errorCode,
                details = mapOf("errorMessage" to errorDescription)
            )
        }.then(
            exchange.setResponse(
                HttpStatus.UNAUTHORIZED,
                "Unable to authenticate: $errorCode: $errorDescription"
            )
        )
    }

    private fun WebFilterExchange.setResponse(responseStatus: HttpStatus, headerMessage: String): Mono<Void> =
        exchange.response.apply {
            statusCode = responseStatus
            headers.add(HttpHeaders.WWW_AUTHENTICATE, headerMessage)
        }.setComplete()

    private fun WebFilterExchange.getRequestErrorCode(): String =
        getRequestParam(OAuth2ParameterNames.ERROR) ?: OAuth2ParameterNames.ERROR

    private fun WebFilterExchange.getRequestErrorDescription(): String? =
        getRequestParam(OAuth2ParameterNames.ERROR_DESCRIPTION)

    private fun WebFilterExchange.getRequestParam(paramName: String) =
        exchange.request.queryParams.toSingleValueMap()[paramName]

    private fun String?.nullIfBlank(): String? = this?.let { it.ifBlank { null } }

    companion object {
        private const val DEFAULT_ERROR_DESCRIPTION = "Authentication failed"
    }
}

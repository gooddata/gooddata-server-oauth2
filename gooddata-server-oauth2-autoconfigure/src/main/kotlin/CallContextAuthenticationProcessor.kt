/*
 * Copyright 2025 GoodData Corporation
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

import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono

private val logger = KotlinLogging.logger {}

/**
 * Context data needed to create a user context.
 */
private data class UserContextData(
    val organizationId: String,
    val userId: String,
    val userName: String?,
    val tokenId: String?,
    val authMethod: AuthMethod?,
    val accessToken: String?
)

/**
 * Processes [CallContextAuthenticationToken] and creates user context from call context data.
 *
 * Unlike other authentication processors, this does NOT fetch organization/user from the authentication store
 * because call context authentication represents requests that have already been authenticated by an upstream
 * service. The upstream service has already validated credentials, checked for global logout, and verified
 * organization/user existence.
 *
 * This processor delegates header parsing to [CallContextHeaderProcessor] implementation.
 */
class CallContextAuthenticationProcessor(
    private val headerProcessor: CallContextHeaderProcessor,
    private val userContextProvider: ReactorUserContextProvider
) : AuthenticationProcessor<CallContextAuthenticationToken>(userContextProvider) {

    override fun authenticate(
        authenticationToken: CallContextAuthenticationToken,
        exchange: ServerWebExchange,
        chain: WebFilterChain
    ): Mono<Void> {
        return try {
            val authDetails = headerProcessor.parseCallContextHeader(authenticationToken.callContextHeaderValue)
                ?: throw CallContextAuthenticationException("Call context header contains no user information")

            val authMethod = try {
                AuthMethod.valueOf(authDetails.authMethod)
            } catch (e: IllegalArgumentException) {
                logger.logError(e) {
                    withAction("callContextAuth")
                    withState("failed")
                    withMessage {
                        "Invalid authMethod '${authDetails.authMethod}' in CallContext header. " +
                            "Valid values: ${AuthMethod.entries.joinToString { it.name }}"
                    }
                }
                throw CallContextAuthenticationException(
                    "Invalid authentication method in call context"
                )
            }

            logger.logInfo {
                withAction("callContextAuth")
                withState("authenticated")
                withOrganizationId(authDetails.organizationId)
                withUserId(authDetails.userId)
                withAuthenticationMethod(authMethod.name)
                authDetails.tokenId?.let { withTokenId(it) }
                withMessage { "Processed authenticated call context" }
            }

            val userContextData = UserContextData(
                organizationId = authDetails.organizationId,
                userId = authDetails.userId,
                userName = null,
                tokenId = authDetails.tokenId,
                authMethod = authMethod,
                accessToken = null
            )
            withUserContext(userContextData) {
                chain.filter(exchange)
            }
        } catch (e: CallContextAuthenticationException) {
            val remoteAddress = exchange.request.remoteAddress?.address?.hostAddress
            logger.logError(e) {
                withAction("callContextAuth")
                withState("failed")
                withMessage { "Call context authentication failed from $remoteAddress" }
            }
            Mono.error(e)
        } catch (@Suppress("TooGenericExceptionCaught") e: Exception) {
            // Must catch all exceptions to prevent auth chain disruption
            logger.logError(e) {
                withAction("callContextAuth")
                withState("error")
                withMessage { "Unexpected error during call context authentication" }
            }
            Mono.error(CallContextAuthenticationException("Authentication failed", e))
        }
    }

    private fun <T> withUserContext(
        userContextData: UserContextData,
        monoProvider: () -> Mono<T>
    ): Mono<T> {
        val contextView = userContextProvider.getContextView(
            organizationId = userContextData.organizationId,
            userId = userContextData.userId,
            userName = userContextData.userName,
            tokenId = userContextData.tokenId,
            authMethod = userContextData.authMethod,
            accessToken = userContextData.accessToken
        )

        return monoProvider().contextWrite(contextView)
    }
}

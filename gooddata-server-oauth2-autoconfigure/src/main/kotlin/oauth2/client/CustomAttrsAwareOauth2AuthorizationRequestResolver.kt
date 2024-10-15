/*
 * Copyright 2024 GoodData Corporation
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
package com.gooddata.oauth2.server.oauth2.client

import com.gooddata.oauth2.server.ReactiveCookieService
import com.gooddata.oauth2.server.SPRING_EXTERNAL_IDP
import com.gooddata.oauth2.server.getOrganizationFromContext
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import reactor.kotlin.core.publisher.switchIfEmpty

/**
 * The implementation of [ServerOAuth2AuthorizationRequestResolver] that is able to append ad-hoc authentication attrs
 * to authorization requests.
 *
 * Firstly it can add an external identity provider (OIDC federation) info to authorization requests
 * based on [SPRING_EXTERNAL_IDP] cookie in the [ServerWebExchange].
 *
 * It wraps the default [ServerOAuth2AuthorizationRequestResolver] which is responsible for building of the original
 * authorization request with standard parameters.
 *
 * When the [SPRING_EXTERNAL_IDP] cookie is present it also clears it because it is not needed anymore.
 *
 * The new query parameter is Cognito-specific for now, so this does not ensure support for other identity providers.
 *
 * Secondly, it can add additional authentication attributes if present in the organization definition.
 *
 * @param defaultResolver the default [ServerOAuth2AuthorizationRequestResolver] to be wrapped
 * @param cookieService the [ReactiveCookieService] to be used for cookie handling
 */
class CustomAttrsAwareOauth2AuthorizationRequestResolver(
    private val defaultResolver: ServerOAuth2AuthorizationRequestResolver,
    private val cookieService: ReactiveCookieService,
) : ServerOAuth2AuthorizationRequestResolver {
    override fun resolve(exchange: ServerWebExchange?): Mono<OAuth2AuthorizationRequest> =
        defaultResolver.resolve(exchange).flatMap { authorizationRequest ->
            enhanceRequestByAdditionalParams(authorizationRequest, exchange)
        }

    override fun resolve(
        exchange: ServerWebExchange?,
        clientRegistrationId: String?,
    ): Mono<OAuth2AuthorizationRequest> =
        defaultResolver.resolve(exchange, clientRegistrationId).flatMap { authorizationRequest ->
            enhanceRequestByAdditionalParams(authorizationRequest, exchange)
        }

    /**
     * Enhances the provided [authorizationRequest] with external additional authentication attributes.
     * Adds additional authentication attributes from the organization definition if they are present.
     * Adds identity provider info based on the [SPRING_EXTERNAL_IDP] cookie existence. If the cookie is present,
     * it is cleared.
     */
    private fun enhanceRequestByAdditionalParams(
        authorizationRequest: OAuth2AuthorizationRequest,
        exchange: ServerWebExchange?,
    ): Mono<OAuth2AuthorizationRequest> = Mono.justOrEmpty(exchange)
        .flatMap { existingExchange ->
            cookieService.decodeCookie(existingExchange, SPRING_EXTERNAL_IDP).map { externalIdp ->
                // invalidate cookie because it is not needed anymore
                cookieService.invalidateCookie(existingExchange, SPRING_EXTERNAL_IDP)
                OAuth2AuthorizationRequest.from(authorizationRequest)
                    .additionalParameters { additionalParams ->
                        // for now, only Cognito federation is supported
                        additionalParams[COGNITO_EXTERNAL_PROVIDER_ID_PARAM_NAME] = externalIdp
                    }
                    .build()
            }.switchIfEmpty {
                Mono.just(authorizationRequest)
            }.flatMap { request ->
                getOrganizationFromContext().flatMap { organization ->
                    Mono.just(OAuth2AuthorizationRequest.from(request)
                        .additionalParameters { additionalParams ->
                            // if organization contains additional authentication attributes, add them to the request
                            organization.oauthCustomAuthAttributes?.takeIf { it.isNotEmpty() }
                                ?.forEach { (key, value) ->
                                    additionalParams[key] = value
                                }
                        }
                        .build()
                    )
                }
            }
        }

    companion object {
        /**
         * Cognito-specific query parameter for external identity provider ID.
         * See https://docs.aws.amazon.com/cognito/latest/developerguide/authorization-endpoint.html#get-authorize.
         */
        private const val COGNITO_EXTERNAL_PROVIDER_ID_PARAM_NAME = "identity_provider"
    }
}

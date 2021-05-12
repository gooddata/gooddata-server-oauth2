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
package com.gooddata.oauth2.server.servlet

import com.gooddata.oauth2.server.common.SPRING_SEC_OAUTH2_AUTHZ_CLIENT
import com.gooddata.oauth2.server.common.jackson.SimplifiedOAuth2AuthorizedClient
import com.gooddata.oauth2.server.common.jackson.mapper
import com.gooddata.oauth2.server.common.jackson.toSimplified
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * Implementation of [OAuth2AuthorizedClientRepository] that stores [OAuth2AuthorizedClient] into
 * `SPRING_SEC_OAUTH2_AUTHZ_CLIENT` HTTP cookie.
 * [org.springframework.security.oauth2.client.registration.ClientRegistration] is not stored there and is loaded
 * from [ClientRegistrationRepository] based on stored clientRegistrationId. This is in contrast to
 * [org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository] that uses
 * HTTP session as a storage.
 *
 * If the cookie cannot be loaded and/or parsed it is as if there was nothing saved.
 */
class CookieOAuth2AuthorizedClientRepository(
    private val clientRegistrationRepository: ClientRegistrationRepository,
    private val cookieService: CookieService,
) : OAuth2AuthorizedClientRepository {

    override fun <T : OAuth2AuthorizedClient> loadAuthorizedClient(
        clientRegistrationId: String,
        principal: Authentication,
        request: HttpServletRequest
    ): T? {
        val authorizedClient =
            cookieService.decodeCookie(
                request,
                SPRING_SEC_OAUTH2_AUTHZ_CLIENT,
                mapper,
                SimplifiedOAuth2AuthorizedClient::class.java
            ) ?: return null

        // verify that loaded OAuth2AuthorizedClient uses provided clientRegistrationId
        val stored = authorizedClient.registrationId
        if (stored != clientRegistrationId) {
            throw IllegalStateException(
                "Stored registrationId $stored does not correspond to expected $clientRegistrationId"
            )
        }
        @Suppress("UNCHECKED_CAST")
        return authorizedClient.toOAuth2AuthorizedClient(clientRegistrationRepository) as T
    }

    override fun saveAuthorizedClient(
        authorizedClient: OAuth2AuthorizedClient,
        principal: Authentication,
        request: HttpServletRequest,
        response: HttpServletResponse
    ) {
        cookieService.createCookie(
            request,
            response,
            SPRING_SEC_OAUTH2_AUTHZ_CLIENT,
            mapper.writeValueAsString(authorizedClient.toSimplified())
        )
    }

    override fun removeAuthorizedClient(
        clientRegistrationId: String,
        principal: Authentication?,
        request: HttpServletRequest,
        response: HttpServletResponse
    ) {
        cookieService.invalidateCookie(request, response, SPRING_SEC_OAUTH2_AUTHZ_CLIENT)
    }

    private fun SimplifiedOAuth2AuthorizedClient.toOAuth2AuthorizedClient(
        clientRegistrationRepository: ClientRegistrationRepository
    ): OAuth2AuthorizedClient {
        val clientRegistration = clientRegistrationRepository.findByRegistrationId(registrationId)
        return OAuth2AuthorizedClient(clientRegistration, principalName, accessToken, refreshToken)
    }
}

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

import com.gooddata.oauth2.server.common.SPRING_SEC_OAUTH2_AUTHZ_RQ
import com.gooddata.oauth2.server.common.jackson.mapper
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * Implementation of [AuthorizationRequestRepository] that persists [OAuth2AuthorizationRequest] into
 * `SPRING_SEC_OAUTH2_AUTHZ_RQ` HTTP cookie. This is in contrast to default
 * [org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository]
 * that uses server-side HTTP session to store all authorization requests being processed.
 *
 * If the cookie cannot be loaded and/or parsed it is as if there was nothing saved.
 */
class CookieAuthorizationRequestRepository(
    private val cookieService: CookieService,
) : AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    override fun loadAuthorizationRequest(request: HttpServletRequest): OAuth2AuthorizationRequest? {
        return cookieService.decodeCookie(
            request,
            SPRING_SEC_OAUTH2_AUTHZ_RQ,
            mapper,
            OAuth2AuthorizationRequest::class.java
        )
    }

    override fun saveAuthorizationRequest(
        authorizationRequest: OAuth2AuthorizationRequest,
        request: HttpServletRequest,
        response: HttpServletResponse
    ) {
        cookieService.createCookie(
            request, response, SPRING_SEC_OAUTH2_AUTHZ_RQ, mapper.writeValueAsString(authorizationRequest)
        )
    }

    override fun removeAuthorizationRequest(request: HttpServletRequest): OAuth2AuthorizationRequest? {
        // cannot remove anything as there is no response object
        return loadAuthorizationRequest(request)
    }

    override fun removeAuthorizationRequest(
        request: HttpServletRequest,
        response: HttpServletResponse
    ): OAuth2AuthorizationRequest? {
        val authRequest = loadAuthorizationRequest(request)
        cookieService.invalidateCookie(request, response, SPRING_SEC_OAUTH2_AUTHZ_RQ)
        return authRequest
    }
}

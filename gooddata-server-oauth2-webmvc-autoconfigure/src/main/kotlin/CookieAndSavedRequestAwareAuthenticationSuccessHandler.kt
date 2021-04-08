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

import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler
import org.springframework.security.web.context.SecurityContextRepository
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * [org.springframework.security.web.authentication.AuthenticationSuccessHandler] that saves current
 * [org.springframework.security.core.context.SecurityContext] to [SecurityContextRepository]. This would normally be
 * done by [org.springframework.security.web.context.SecurityContextPersistenceFilter] but in case some underlying
 * [javax.servlet.Filter] redirects the response it would commit it and prevent any further updates.
 */
class CookieAndSavedRequestAwareAuthenticationSuccessHandler(
    private val securityContextRepository: SecurityContextRepository,
) : SavedRequestAwareAuthenticationSuccessHandler() {

    override fun onAuthenticationSuccess(
        request: HttpServletRequest?,
        response: HttpServletResponse?,
        authentication: Authentication?
    ) {
        securityContextRepository.saveContext(SecurityContextHolder.getContext(), request, response)
        super.onAuthenticationSuccess(request, response, authentication)
    }
}

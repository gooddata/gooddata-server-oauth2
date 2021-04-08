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
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler
import org.springframework.security.web.context.SecurityContextRepository
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * [SecurityContextLogoutHandler] that clears [org.springframework.security.core.context.SecurityContext] from
 * [SecurityContextRepository].
 */
class SecurityContextClearingLogoutHandler(
    private val securityContextRepository: SecurityContextRepository,
) : SecurityContextLogoutHandler() {

    override fun logout(
        request: HttpServletRequest?,
        response: HttpServletResponse?,
        authentication: Authentication?
    ) {
        super.logout(request, response, authentication)
        securityContextRepository.saveContext(SecurityContextImpl(), request, response)
    }
}

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

import com.gooddata.oauth2.server.common.AuthenticationStoreClient
import com.gooddata.oauth2.server.common.userContextAuthenticationToken
import kotlinx.coroutines.runBlocking
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationManagerResolver
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken
import javax.servlet.http.HttpServletRequest

/**
 * [AuthenticationManagerResolver] that is able to authenticate bearer tokens.
 */
class BearerTokenAuthenticationManagerResolver(
    private val client: AuthenticationStoreClient,
) : AuthenticationManagerResolver<HttpServletRequest> {

    override fun resolve(request: HttpServletRequest): AuthenticationManager =
        AuthenticationManager { authentication ->
            (authentication as? BearerTokenAuthenticationToken)?.let {
                runBlocking {
                    userContextAuthenticationToken(client, request.serverName, it)
                }
            }
        }
}

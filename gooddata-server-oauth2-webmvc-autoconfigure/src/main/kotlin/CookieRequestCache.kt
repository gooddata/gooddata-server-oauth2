/*
 * Copyright 2002-2020 the original author or authors.
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
 *
 * Forked from https://github.com/spring-projects/spring-security/blob/5.4.0/web/src/main/java/org/springframework/security/web/savedrequest/CookieRequestCache.java
 */
package com.gooddata.oauth2.server.servlet

import com.gooddata.oauth2.server.common.SPRING_REDIRECT_URI
import org.springframework.security.web.savedrequest.RequestCache
import org.springframework.security.web.savedrequest.SavedRequest
import org.springframework.security.web.savedrequest.SimpleSavedRequest
import org.springframework.security.web.util.UrlUtils
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * An Implementation of `RequestCache` which saves the original request URI in a cookie.
 *
 * @author Zeeshan Adnan
 * @since 5.4
 */
class CookieRequestCache(private val cookieService: CookieService) : RequestCache {
    private val requestMatcher = AntPathRequestMatcher("/**", "GET")

    override fun saveRequest(request: HttpServletRequest, response: HttpServletResponse) {
        if (!requestMatcher.matches(request)) {
            return
        }
        val redirectUrl = UrlUtils.buildRequestUrl(request)
        cookieService.createCookie(request, response, SPRING_REDIRECT_URI, redirectUrl)
    }

    override fun getRequest(request: HttpServletRequest, response: HttpServletResponse): SavedRequest? {
        val redirectUrl = cookieService.decodeCookie(request, SPRING_REDIRECT_URI) ?: return null
        return SimpleSavedRequest(redirectUrl)
    }

    override fun getMatchingRequest(request: HttpServletRequest, response: HttpServletResponse): HttpServletRequest? {
        val saved = getRequest(request, response)
        if (!matchesSavedRequest(request, saved)) {
            return null
        }
        removeRequest(request, response)
        // cached request does contain only request path so we return current request instead
        return request
    }

    override fun removeRequest(request: HttpServletRequest, response: HttpServletResponse) {
        cookieService.invalidateCookie(request, response, SPRING_REDIRECT_URI)
    }

    private fun matchesSavedRequest(request: HttpServletRequest, savedRequest: SavedRequest?): Boolean {
        if (savedRequest == null) {
            return false
        }
        val currentUrl = UrlUtils.buildRequestUrl(request)
        return savedRequest.redirectUrl == currentUrl
    }
}

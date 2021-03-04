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

import org.apache.commons.logging.Log
import org.apache.commons.logging.LogFactory
import org.springframework.security.web.savedrequest.DefaultSavedRequest
import org.springframework.security.web.savedrequest.RequestCache
import org.springframework.security.web.savedrequest.SavedRequest
import org.springframework.security.web.util.UrlUtils
import org.springframework.security.web.util.matcher.AnyRequestMatcher
import org.springframework.security.web.util.matcher.RequestMatcher
import org.springframework.util.Assert
import org.springframework.util.MultiValueMap
import org.springframework.web.util.UriComponents
import org.springframework.web.util.UriComponentsBuilder
import org.springframework.web.util.WebUtils
import java.util.Base64
import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * An Implementation of `RequestCache` which saves the original request URI in a
 * cookie.
 *
 * @author Zeeshan Adnan
 * @since 5.4
 */
class CookieRequestCache : RequestCache {
    private var requestMatcher: RequestMatcher = AnyRequestMatcher.INSTANCE
    protected val logger: Log = LogFactory.getLog(this.javaClass)
    override fun saveRequest(request: HttpServletRequest, response: HttpServletResponse) {
        if (!requestMatcher.matches(request)) {
            logger.debug("Request not saved as configured RequestMatcher did not match")
            return
        }
        val redirectUrl: String = UrlUtils.buildFullRequestUrl(request)
        val savedCookie = Cookie(COOKIE_NAME, encodeCookie(redirectUrl))
        savedCookie.setMaxAge(COOKIE_MAX_AGE)
        savedCookie.setSecure(request.isSecure())
        savedCookie.setPath(getCookiePath(request))
        savedCookie.setHttpOnly(true)
        response.addCookie(savedCookie)
    }

    override fun getRequest(request: HttpServletRequest, response: HttpServletResponse?): SavedRequest? {
        val savedRequestCookie: Cookie = WebUtils.getCookie(request, COOKIE_NAME)
            ?: return null
        val originalURI = decodeCookie(savedRequestCookie.getValue())
        val uriComponents: UriComponents = UriComponentsBuilder.fromUriString(originalURI).build()
        val builder: DefaultSavedRequest.Builder = DefaultSavedRequest.Builder()
        val port = getPort(uriComponents)
        val queryParams: MultiValueMap<String, String> = uriComponents.getQueryParams()
        if (!queryParams.isEmpty()) {
            val parameters: HashMap<String, Array<String>> = HashMap(queryParams.size)
            queryParams.forEach { key, value -> parameters[key] = value.toTypedArray() }
            builder.setParameters(parameters)
        }
        return builder.setScheme(uriComponents.getScheme()).setServerName(uriComponents.getHost())
            .setRequestURI(uriComponents.getPath()).setQueryString(uriComponents.getQuery()).setServerPort(port)
            .setMethod(request.getMethod()).build()
    }

    @Suppress("MagicNumber")
    private fun getPort(uriComponents: UriComponents): Int {
        val port: Int = uriComponents.getPort()
        if (port != -1) {
            return port
        }
        return if ("https".equals(uriComponents.getScheme(), ignoreCase = true)) {
            443
        } else 80
    }

    override fun getMatchingRequest(request: HttpServletRequest, response: HttpServletResponse): HttpServletRequest? {
        val saved: SavedRequest? = getRequest(request, response)
        if (!matchesSavedRequest(request, saved)) {
            logger.debug("saved request doesn't match")
            return null
        }
        removeRequest(request, response)
        return SavedRequestAwareWrapper(saved, request)
    }

    override fun removeRequest(request: HttpServletRequest, response: HttpServletResponse) {
        val removeSavedRequestCookie = Cookie(COOKIE_NAME, "")
        removeSavedRequestCookie.setSecure(request.isSecure())
        removeSavedRequestCookie.setHttpOnly(true)
        removeSavedRequestCookie.setPath(getCookiePath(request))
        removeSavedRequestCookie.setMaxAge(0)
        response.addCookie(removeSavedRequestCookie)
    }

    private fun matchesSavedRequest(request: HttpServletRequest, savedRequest: SavedRequest?): Boolean {
        if (savedRequest == null) {
            return false
        }
        val currentUrl: String = UrlUtils.buildFullRequestUrl(request)
        return savedRequest.getRedirectUrl().equals(currentUrl)
    }

    /**
     * Allows selective use of saved requests for a subset of requests. By default any
     * request will be cached by the `saveRequest` method.
     *
     *
     * If set, only matching requests will be cached.
     * @param requestMatcher a request matching strategy which defines which requests
     * should be cached.
     */
    fun setRequestMatcher(requestMatcher: RequestMatcher) {
        Assert.notNull(requestMatcher, "requestMatcher should not be null")
        this.requestMatcher = requestMatcher
    }

    companion object {
        private const val COOKIE_NAME = "REDIRECT_URI"
        private const val COOKIE_MAX_AGE = -1
        private fun encodeCookie(cookieValue: String): String {
            return Base64.getEncoder().encodeToString(cookieValue.toByteArray())
        }

        private fun decodeCookie(encodedCookieValue: String): String {
            return String(Base64.getDecoder().decode(encodedCookieValue.toByteArray()))
        }

        private fun getCookiePath(request: HttpServletRequest): String {
            val contextPath: String = request.getContextPath()
            return if (contextPath.isNotEmpty()) contextPath else "/"
        }
    }
}

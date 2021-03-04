/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

import org.apache.commons.logging.LogFactory
import org.springframework.security.web.savedrequest.Enumerator
import org.springframework.security.web.savedrequest.FastHttpDateFormat
import org.springframework.security.web.savedrequest.SavedRequest
import java.text.SimpleDateFormat
import java.util.ArrayList
import java.util.Enumeration
import java.util.Locale
import java.util.TimeZone
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletRequestWrapper

/**
 * Provides request parameters, headers and cookies from either an original request or a
 * saved request.
 *
 *
 *
 * Note that not all request parameters in the original request are emulated by this
 * wrapper. Nevertheless, the important data from the original request is emulated and
 * this should prove adequate for most purposes (in particular standard HTTP GET and POST
 * operations).
 *
 *
 *
 * Added into a request by
 * [org.springframework.security.web.savedrequest.RequestCacheAwareFilter].
 *
 * @author Andrey Grebnev
 * @author Ben Alex
 * @author Luke Taylor
 */
internal class SavedRequestAwareWrapper(saved: SavedRequest?, request: HttpServletRequest?) :
    HttpServletRequestWrapper(request) {
    protected var savedRequest: SavedRequest

    /**
     * The set of SimpleDateFormat formats to use in getDateHeader(). Notice that because
     * SimpleDateFormat is not thread-safe, we can't declare formats[] as a static
     * variable.
     */
    @Suppress("MagicNumber")
    protected val formats = arrayOfNulls<SimpleDateFormat>(3)

    init {
        savedRequest = saved!!
        formats[0] = SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US)
        formats[1] = SimpleDateFormat("EEEEEE, dd-MMM-yy HH:mm:ss zzz", Locale.US)
        formats[2] = SimpleDateFormat("EEE MMMM d HH:mm:ss yyyy", Locale.US)
        formats[0]!!.timeZone = GMT_ZONE
        formats[1]!!.timeZone = GMT_ZONE
        formats[2]!!.timeZone = GMT_ZONE
    }

    override fun getDateHeader(name: String): Long {
        val value = getHeader(name) ?: return -1L
        // Attempt to convert the date header in a variety of formats
        val result: Long = FastHttpDateFormat.parseDate(value, formats)
        if (result != -1L) {
            return result
        }
        throw IllegalArgumentException(value)
    }

    override fun getHeader(name: String): String? {
        val values: List<String> = savedRequest.getHeaderValues(name)
        return if (values.isEmpty()) null else values[0]
    }

    override fun getHeaderNames(): Enumeration<String>? {
        return Enumerator(savedRequest.getHeaderNames())
    }

    override fun getHeaders(name: String): Enumeration<String>? {
        return Enumerator(savedRequest.getHeaderValues(name))
    }

    override fun getIntHeader(name: String): Int {
        val value = getHeader(name)
        return value?.toInt() ?: -1
    }

    override fun getLocale(): Locale {
        val locales: List<Locale> = savedRequest.getLocales()
        return if (locales.isEmpty()) Locale.getDefault() else locales[0]
    }

    override fun getLocales(): Enumeration<Locale>? {
        var locales: MutableList<Locale?> = savedRequest.getLocales()
        if (locales.isEmpty()) {
            // Fall back to default locale
            locales = ArrayList(1)
            locales.add(Locale.getDefault())
        }
        return Enumerator(locales)
    }

    override fun getMethod(): String {
        return savedRequest.getMethod()
    }

    /**
     * If the parameter is available from the wrapped request then the request has been
     * forwarded/included to a URL with parameters, either supplementing or overriding the
     * saved request values.
     *
     *
     * In this case, the value from the wrapped request should be used.
     *
     *
     * If the value from the wrapped request is null, an attempt will be made to retrieve
     * the parameter from the saved request.
     */
    override fun getParameter(name: String): String? {
        val value = super.getParameter(name)
        if (value != null) {
            return value
        }
        val values: Array<String> = savedRequest.getParameterValues(name)
        return if (values.size == 0) {
            null
        } else values[0]
    }

    override fun getParameterMap(): MutableMap<String, Array<String>>? {
        val names = combinedParameterNames
        val parameterMap: MutableMap<String, Array<String>> = HashMap(names.size)
        for (name in names) {
            parameterMap[name] = getParameterValues(name)
        }
        return parameterMap
    }

    private val combinedParameterNames: Set<String>
        get() {
            val names: MutableSet<String> = HashSet()
            names.addAll(super.getParameterMap().keys)
            names.addAll(savedRequest.getParameterMap().keys)
            return names
        }

    override fun getParameterNames(): Enumeration<String>? {
        return Enumerator(combinedParameterNames)
    }

    @Suppress("ReturnCount", "SpreadOperator")
    override fun getParameterValues(name: String): Array<String> {
        val savedRequestParams: Array<String> = savedRequest.getParameterValues(name)
        val wrappedRequestParams = super.getParameterValues(name)
        if (wrappedRequestParams == null) {
            return savedRequestParams
        }
        // We have parameters in both saved and wrapped requests so have to merge them
        val wrappedParamsList = listOf(*wrappedRequestParams)
        val combinedParams: MutableList<String> = ArrayList(wrappedParamsList)
        // We want to add all parameters of the saved request *apart from* duplicates of
        // those already added
        for (savedRequestParam in savedRequestParams) {
            if (!wrappedParamsList.contains(savedRequestParam)) {
                combinedParams.add(savedRequestParam)
            }
        }
        return combinedParams.toTypedArray()
    }

    companion object {
        protected val logger = LogFactory.getLog(SavedRequestAwareWrapper::class.java)
        protected val GMT_ZONE = TimeZone.getTimeZone("GMT")

        /** The default Locale if none are specified.  */
        protected var defaultLocale = Locale.getDefault()
    }
}

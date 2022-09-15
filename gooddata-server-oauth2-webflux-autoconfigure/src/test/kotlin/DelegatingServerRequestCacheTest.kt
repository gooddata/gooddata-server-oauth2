/*
 * Copyright 2022 GoodData Corporation
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
package com.gooddata.oauth2.server.reactive

import io.mockk.Called
import io.mockk.every
import io.mockk.invoke
import io.mockk.mockk
import io.mockk.verify
import org.junit.jupiter.api.Test
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

@Suppress("ReactiveStreamsUnusedPublisher")
internal class DelegatingServerRequestCacheTest {

    private val exchange = mockk<ServerWebExchange>()
    private val appLoginCookieRequestCacheWriter = mockk<AppLoginCookieRequestCacheWriter>(relaxed = true)
    private val appLoginRedirectProcessor = mockk<AppLoginRedirectProcessor>()
    private val serverRequestCache = mockk<CookieServerRequestCache> {
        every { saveRequest(any()) } returns Mono.empty()
        every { getRedirectUri(any()) } returns Mono.empty()
        every { removeMatchingRequest(any()) } returns Mono.empty()
    }
    private val delegatingRequestCache: DelegatingServerRequestCache by lazy {
        DelegatingServerRequestCache(serverRequestCache, appLoginCookieRequestCacheWriter, appLoginRedirectProcessor)
    }

    @Test
    fun `saves standard request to cache`() {
        every { appLoginRedirectProcessor.process(exchange, any(), captureLambda()) } answers {
            lambda<() -> Mono<Void>>().invoke()
        }

        delegatingRequestCache.saveRequest(exchange).block()

        verify { serverRequestCache.saveRequest(exchange) }
        verify { appLoginCookieRequestCacheWriter wasNot Called }
    }

    @Test
    fun `saves appLogin request to cache`() {
        every { appLoginRedirectProcessor.process(exchange, captureLambda(), any()) } answers {
            lambda<(String) -> Mono<Void>>().invoke("/some/path")
        }

        delegatingRequestCache.saveRequest(exchange).block()

        verify { serverRequestCache wasNot Called }
        verify { appLoginCookieRequestCacheWriter.saveRequest(exchange, "/some/path") }
    }

    @Test
    fun `uses getRedirectUri from standard request cache`() {
        delegatingRequestCache.getRedirectUri(exchange).block()
        verify { serverRequestCache.getRedirectUri(exchange) }
    }

    @Test
    fun `uses removeMatchingRequest from standard request cache`() {
        delegatingRequestCache.removeMatchingRequest(exchange).block()
        verify { serverRequestCache.removeMatchingRequest(exchange) }
    }
}

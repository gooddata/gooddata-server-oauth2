/*
 * (C) 2022 GoodData Corporation
 */

package com.gooddata.oauth2.server

import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Test
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.reactive.CorsConfigurationSource
import org.springframework.web.server.ServerWebExchange
import strikt.api.expectThat
import strikt.assertions.isEqualTo
import java.net.URI

class CompositeCorsConfigurationSourceTest {

    private val corsConfigurationSource = mockk<CorsConfigurationSource>()

    private val organizationCorsConfigurationSource = OrganizationCorsConfigurationSource(GLOBAL_ALLOWED_HOST)

    private val exchange = mockk<ServerWebExchange>()

    private val compositeCorsConfigurationSource = CompositeCorsConfigurationSource(
        corsConfigurationSource,
        organizationCorsConfigurationSource
    )

    @Test
    fun `WHEN allowedOrigins is null THEN cors configuration must allow the global redirect uri`() {
        every { corsConfigurationSource.getCorsConfiguration(exchange) } returns null
        every { exchange.attributes[OrganizationWebFilter.ORGANIZATION_CACHE_KEY] } returns Organization(
            id = ORGANIZATION_HOST,
            allowedOrigins = null
        )
        val request = mockk<ServerHttpRequest>()
        every { request.uri } returns URI("http", ORGANIZATION_HOST, "/path", null)
        every { exchange.request } returns request

        expectAllowedHosts(GLOBAL_ALLOWED_HOST)
    }

    @Test
    fun `WHEN allowedOrigins is not null THEN cors configuration must contain only org allowed origins`() {
        every { corsConfigurationSource.getCorsConfiguration(exchange) } returns null
        every { exchange.attributes[OrganizationWebFilter.ORGANIZATION_CACHE_KEY] } returns Organization(
            id = ORGANIZATION_HOST,
            allowedOrigins = listOf(ALLOWED_HOST)
        )
        val request = mockk<ServerHttpRequest>()
        every { request.uri } returns URI("http", ORGANIZATION_HOST, "/path", null)
        every { exchange.request } returns request

        expectAllowedHosts(ALLOWED_HOST)
    }

    private fun expectAllowedHosts(host: String) {
        expectThat(compositeCorsConfigurationSource.getCorsConfiguration(exchange)) {
            get { allowedOrigins }.isEqualTo(listOf(host))
            get { allowedMethods }.isEqualTo(listOf(CorsConfiguration.ALL))
            get { allowedHeaders }.isEqualTo(listOf(CorsConfiguration.ALL))
        }
    }

    companion object {
        const val GLOBAL_ALLOWED_HOST = "someglobalhost"
        const val ALLOWED_HOST = "somehost"
        const val ORGANIZATION_HOST = "orghost"
    }
}

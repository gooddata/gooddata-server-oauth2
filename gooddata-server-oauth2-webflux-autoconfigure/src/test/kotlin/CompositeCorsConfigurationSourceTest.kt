/*
 * (C) 2022 GoodData Corporation
 */

package com.gooddata.oauth2.server.reactive

import com.gooddata.oauth2.server.common.OrganizationCorsConfigurationSource
import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Test
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.reactive.CorsConfigurationSource
import org.springframework.web.server.ServerWebExchange
import strikt.api.expectThat
import strikt.assertions.isEqualTo
import strikt.assertions.isNotNull
import strikt.assertions.isSameInstanceAs
import java.net.URI

class CompositeCorsConfigurationSourceTest {

    private val corsConfigurationSource = mockk<CorsConfigurationSource>()

    private val organizationCorsConfigurationSource = mockk<OrganizationCorsConfigurationSource>()

    private val exchange = mockk<ServerWebExchange>()

    private val compositeCorsConfigurationSource = CompositeCorsConfigurationSource(
        corsConfigurationSource,
        organizationCorsConfigurationSource,
        ALLOWED_HOST
    )

    @Test
    fun `getCorsConfiguration returns AllowedHost for null exchange request uri host`() {
        every { corsConfigurationSource.getCorsConfiguration(exchange) } returns null

        val request = mockk<ServerHttpRequest>()
        every { request.uri } returns URI("http", null, "/path", null)
        every { exchange.request } returns request

        expectAllowedHosts()
    }

    @Test
    fun `getCorsConfiguration returns AllowedHost when no configuration found in sources`() {
        every { corsConfigurationSource.getCorsConfiguration(exchange) } returns null

        val request = mockk<ServerHttpRequest>()
        every { request.uri } returns URI("http", ORGANIZATION_HOST, "/path", null)
        every { exchange.request } returns request

        every { organizationCorsConfigurationSource.getOrganizationCorsConfiguration(ORGANIZATION_HOST) } returns null

        expectAllowedHosts()
    }

    @Test
    fun `getCorsConfiguration returns configuration found in organization sources`() {
        every { corsConfigurationSource.getCorsConfiguration(exchange) } returns null

        val request = mockk<ServerHttpRequest>()
        every { request.uri } returns URI("http", ORGANIZATION_HOST, "/path", null)
        every { exchange.request } returns request

        val organizationCorsConfiguration = CorsConfiguration()

        every {
            organizationCorsConfigurationSource.getOrganizationCorsConfiguration(ORGANIZATION_HOST)
        } returns organizationCorsConfiguration

        expectThat(compositeCorsConfigurationSource.getCorsConfiguration(exchange))
            .isSameInstanceAs(organizationCorsConfiguration)
    }

    @Test
    fun `getCorsConfiguration returns configuration found in custom sources`() {
        every { corsConfigurationSource.getCorsConfiguration(exchange) } returns null

        val request = mockk<ServerHttpRequest>()
        every { request.uri } returns URI("http", ORGANIZATION_HOST, "/path", null)
        every { exchange.request } returns request

        val organizationCorsConfiguration = CorsConfiguration()
        every {
            organizationCorsConfigurationSource.getOrganizationCorsConfiguration(ORGANIZATION_HOST)
        } returns organizationCorsConfiguration

        val corsConfiguration = CorsConfiguration()
        every {
            corsConfigurationSource.getCorsConfiguration(exchange)
        } returns corsConfiguration

        expectThat(compositeCorsConfigurationSource.getCorsConfiguration(exchange)).isSameInstanceAs(corsConfiguration)
    }

    private fun expectAllowedHosts() {
        expectThat(compositeCorsConfigurationSource.getCorsConfiguration(exchange)).isNotNull().and {
            get { allowedOrigins }.isEqualTo(listOf(ALLOWED_HOST))
            get { allowedMethods }.isEqualTo(listOf(CorsConfiguration.ALL))
            get { allowedHeaders }.isEqualTo(listOf(CorsConfiguration.ALL))
        }
    }

    companion object {
        const val ALLOWED_HOST = "somehost"
        const val ORGANIZATION_HOST = "orghost"
    }
}

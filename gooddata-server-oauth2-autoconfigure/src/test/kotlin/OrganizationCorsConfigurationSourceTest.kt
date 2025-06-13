/*
 * (C) 2022 GoodData Corporation
 */

package com.gooddata.oauth2.server

import com.gooddata.oauth2.server.OrganizationWebFilter.Companion.ORGANIZATION_CACHE_KEY
import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Test
import org.springframework.web.server.ServerWebExchange
import strikt.api.expectThat
import strikt.assertions.isEqualTo

class OrganizationCorsConfigurationSourceTest {

    private val organizationCorsConfigurationSource = OrganizationCorsConfigurationSource(
        AppLoginProperties.GLOBAL_REDIRECT_DEFAULT
    )

    @Test
    fun `getOrganizationCorsConfiguration correctly separates allowed origins and allowed origin patterns`() {
        val exchange = mockk<ServerWebExchange>()
        every { exchange.attributes } returns mapOf(
            ORGANIZATION_CACHE_KEY to Organization(
                id = "org",
                allowedOrigins = listOf(ALLOWED_HOST, ALLOWED_HOST_WILDCARD)
            )
        )

        expectThat(organizationCorsConfigurationSource.getOrganizationCorsConfiguration(exchange)) {
            get { allowedOrigins }.isEqualTo(listOf(ALLOWED_HOST))
            get { allowedOriginPatterns }.isEqualTo(listOf(ALLOWED_HOST_WILDCARD))
        }
    }

    companion object {
        const val ALLOWED_HOST = "somehost"
        const val ALLOWED_HOST_WILDCARD = "*.somehost"
    }
}

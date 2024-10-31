/*
 * (C) 2022 GoodData Corporation
 */
package com.gooddata.oauth2.server

import io.mockk.mockk
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import org.springframework.mock.web.server.MockServerWebExchange
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.web.server.WebFilterChain
import strikt.api.expectThat
import strikt.assertions.isEqualTo
import strikt.assertions.isFalse
import strikt.assertions.isTrue

class UriExtensionsTest {
    @Test
    fun `text to URI`() {
        val uri = "http://localhost:3000/logout?user=emil".toUri()
        expectThat(uri.host).isEqualTo("localhost")
        expectThat(uri.port).isEqualTo(3000)
        expectThat(uri.path).isEqualTo("/logout")
    }

    @Test
    fun `get base URL`() {
        val uri = "http://localhost:3000/logout?user=emil".toUri()
        expectThat(uri.baseUrl().toString()).isEqualTo("http://localhost:3000")
    }

    @Test
    fun `valid Auth0 issuer`() {
        val uri = "https://dev-abcd1234.auth0.com".toUri()
        expectThat(uri.isAuth0()).isTrue()
    }

    @Test
    fun `invalid Auth0 issuer`() {
        val uri = "https://auth0.example.org".toUri()
        expectThat(uri.isAuth0()).isFalse()
    }

    @Test
    fun `returnToQueryParam should return correct query parameter`() {
        val request = MockServerHttpRequest.get("http://localhost?returnTo=urlToReturnTo")
        val exchange = MockServerWebExchange.from(request)
        val chain = mockk<WebFilterChain>()
        val webFilterExchange = WebFilterExchange(exchange, chain)

        expectThat(webFilterExchange.returnToQueryParam()).isEqualTo("urlToReturnTo")
    }

    @Test
    fun `valid Cognito issuer`() {
        val uri = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abcd1234".toUri()
        expectThat(uri.isCognito()).isTrue()
    }

    @ParameterizedTest
    @ValueSource(strings = [
        "https://amazonaws.cognito-idp.example.org",
        "https://amazonaws.example.org",
        "https://cognito-idp.amazonaws.example.com",
        "https://cognito-idp.example.com"
    ])
    fun `invalid Cognito issuer`(issuer: String) {
        val uri = issuer.toUri()
        expectThat(uri.isCognito()).isFalse()
    }

    @ParameterizedTest
    @ValueSource(strings = [
        "https://tenant.b2clogin.com/tenant.onmicrosoft.com/policy/v2.0",
        "https://tenant.b2clogin.com/tenant.onmicrosoft.com/policy",
        "https://tenant.b2clogin.com/tenant.onmicrosoft.com/policy/v2.0/",
        "https://tenant.b2clogin.com/tenant.onmicrosoft.com/policy/"
    ])
    fun `valid Azure B2C issuer`(issuer: String) {
        val uri = (issuer)
            .toUri()
        expectThat(uri.isAzureB2C()).isTrue()
    }

    @ParameterizedTest
    @ValueSource(strings = [
        "https://b2clogin.azure-idp.example.org",
        "https://onmicrosoft.b2clogin.com",
        "https://onmicrosoft-idp.b2clogin.example.com",
        "https://tenant.b2clogin.com/onmicrosoft.com/policy"
    ])
    fun `invalid Azure B2C issuer`(issuer: String) {
        val uri = issuer.toUri()
        expectThat(uri.isAzureB2C()).isFalse()
    }
}

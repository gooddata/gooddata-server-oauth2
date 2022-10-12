/*
 * (C) 2022 GoodData Corporation
 */
package com.gooddata.oauth2.server

import org.junit.jupiter.api.Test
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
}

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
package com.gooddata.oauth2.server

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import net.javacrumbs.jsonunit.core.util.ResourceUtils
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException
import org.springframework.web.server.ServerWebExchange
import strikt.api.expectThat
import strikt.api.expectThrows
import strikt.assertions.isEqualTo
import strikt.assertions.isNotNull
import strikt.assertions.isNull
import strikt.assertions.isTrue

internal class BearerTokenReactiveAuthenticationManagerResolverTest {

    private val client: AuthenticationStoreClient = mockk()

    @Test
    fun `authenticates incorrect token type`() {
        val resolver = BearerTokenReactiveAuthenticationManagerResolver(client)
        val manager = resolver.resolve(mockk()).block()!!

        expectThat(manager.authenticate(mockk<OAuth2AuthenticationToken>()).block()) { isNull() }
    }

    @Test
    fun `authenticates incorrect bearer token`() {
        val exchange: ServerWebExchange = mockk {
            every { request.uri.host } returns HOST
        }
        coEvery { client.getOrganizationByHostname(HOST) } returns Organization(ORG_ID)
        coEvery { client.getUserByApiToken(ORG_ID, "invalid") } throws InvalidBearerTokenException("")
        val resolver = BearerTokenReactiveAuthenticationManagerResolver(client)
        val manager = resolver.resolve(exchange).block()!!

        expectThrows<InvalidBearerTokenException> {
            manager.authenticate(BearerTokenAuthenticationToken("invalid")).awaitOrNull()
        }
    }

    @Test
    fun `authenticates valid bearer token`() {
        val exchange: ServerWebExchange = mockk {
            every { request.uri.host } returns HOST
        }
        coEvery { client.getOrganizationByHostname(HOST) } returns Organization(ORG_ID)
        coEvery { client.getUserByApiToken(ORG_ID, TOKEN) } returns User(USER_ID)

        val resolver = BearerTokenReactiveAuthenticationManagerResolver(client)
        val manager = resolver.resolve(exchange).block()!!

        val authenticated = manager.authenticate(BearerTokenAuthenticationToken(TOKEN)).block()
        expectThat(authenticated) {
            isNotNull().get(Authentication::isAuthenticated).isTrue()
        }
    }

    @Test
    fun `authenticates valid bearer JWT token`() {
        val exchange: ServerWebExchange = mockk {
            every { request.uri.host } returns HOST
        }

        coEvery { client.getOrganizationByHostname(HOST) } returns Organization(ORG_ID)
        coEvery { client.getJwks(ORG_ID) } returns listOf(buildJwk(PUBLIC_KEY))

        val resolver = BearerTokenReactiveAuthenticationManagerResolver(client)
        val manager = resolver.resolve(exchange).block()!!

        val authenticated = manager.authenticate(
            BearerTokenAuthenticationToken(VALID_JWT)
        ).block()
        expectThat(authenticated) {
            isNotNull().get(Authentication::isAuthenticated).isTrue()
        }
    }

    @Test
    fun `authentication fails when no JWK configured for the organization`() {
        val exchange: ServerWebExchange = mockk {
            every { request.uri.host } returns HOST
        }

        coEvery { client.getOrganizationByHostname(HOST) } returns Organization(ORG_ID)
        coEvery { client.getJwks(ORG_ID) } returns emptyList()

        val resolver = BearerTokenReactiveAuthenticationManagerResolver(client)
        val manager = resolver.resolve(exchange).block()!!

        expectThrows<InvalidBearerTokenException> {
            manager.authenticate(BearerTokenAuthenticationToken(VALID_JWT)).block()
        }.and {
            get { message }.isEqualTo("Signed JWT rejected: Another algorithm expected, or no matching key(s) found")
        }
    }

    @Test
    fun `authentication fails for expired JWT`() {
        val exchange: ServerWebExchange = mockk {
            every { request.uri.host } returns HOST
        }

        coEvery { client.getOrganizationByHostname(HOST) } returns Organization(ORG_ID)
        coEvery { client.getJwks(ORG_ID) } returns listOf(buildJwk(PUBLIC_KEY))

        val resolver = BearerTokenReactiveAuthenticationManagerResolver(client)
        val manager = resolver.resolve(exchange).block()!!

        expectThrows<InvalidBearerTokenException> {
            manager.authenticate(BearerTokenAuthenticationToken(EXPIRED_JWT)).block()
        }.and {
            get { message }.isEqualTo("JWT has expired.")
        }
    }

    @ParameterizedTest
    @ValueSource(strings = ["jku", "x5u", "jwk", "x5c"])
    fun `authentication fails for JWT with invalid fields`(parameterName: String) {
        val exchange: ServerWebExchange = mockk {
            every { request.uri.host } returns HOST
        }

        coEvery { client.getOrganizationByHostname(HOST) } returns Organization(ORG_ID)
        coEvery { client.getJwks(ORG_ID) } returns listOf(buildJwk(PUBLIC_KEY))

        val resolver = BearerTokenReactiveAuthenticationManagerResolver(client)
        val manager = resolver.resolve(exchange).block()!!

        val invalidJwt = ResourceUtils.resource("jwt/jwt_invalid_par_$parameterName.txt").readText()

        expectThrows<InvalidBearerTokenException> {
            manager.authenticate(BearerTokenAuthenticationToken(invalidJwt)).block()
        }.and {
            get { message }.isEqualTo("Jwt contains not allowed header parameter \"$parameterName\".")
        }
    }

    @Test
    fun `test auth failed for invalid header`() {
        val exchange: ServerWebExchange = mockk {
            every { request.uri.host } returns HOST
        }

        coEvery { client.getOrganizationByHostname(HOST) } returns Organization(ORG_ID)
        coEvery { client.getJwks(ORG_ID) } returns listOf(buildJwk(PUBLIC_KEY))

        val resolver = BearerTokenReactiveAuthenticationManagerResolver(client)
        val manager = resolver.resolve(exchange).block()!!

        val invalidJwt = ResourceUtils.resource("jwt/jwt_invalid_type.txt").readText()

        expectThrows<InvalidBearerTokenException> {
            manager.authenticate(BearerTokenAuthenticationToken(invalidJwt)).block()
        }.and {
            get { message }.isEqualTo("Invalid jws header. Header must be of JWT type and with non-null keyId.")
        }
    }

    private fun buildJwk(publicKey: PublicKey): RSAKey {
        val rawJwk = JWK.parseFromPEMEncodedObjects(publicKey.value) as RSAKey
        return RSAKey.Builder(rawJwk)
            .keyID(publicKey.id)
            .algorithm(publicKey.algorithm)
            .keyUse(publicKey.useAs)
            .build()
    }

    data class PublicKey(
        val id: String,
        val value: String,
        val algorithm: Algorithm = Algorithm.parse("RS256"),
        val useAs: KeyUse = KeyUse.SIGNATURE
    )

    companion object {
        private const val HOST = "localhost"
        private const val ORG_ID = "organizationId"
        private const val USER_ID = "userId"
        private const val TOKEN = "supersecuretoken"
        private const val PUBLIC_KEY_ID = "key.1"

        private val PUBLIC_KEY_VALUE = ResourceUtils.resource("jwt/jwk_public_key.txt").readText()
        private val PUBLIC_KEY = PublicKey(PUBLIC_KEY_ID, PUBLIC_KEY_VALUE)

        private val VALID_JWT = ResourceUtils.resource("jwt/jwt_valid.txt").readText()
        private val EXPIRED_JWT = ResourceUtils.resource("jwt/jwt_expired.txt").readText()
    }
}

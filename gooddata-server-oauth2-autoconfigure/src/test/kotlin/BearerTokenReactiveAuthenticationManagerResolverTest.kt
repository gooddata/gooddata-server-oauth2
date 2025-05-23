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

import com.gooddata.oauth2.server.OrganizationWebFilter.Companion.orgContextWrite
import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import net.javacrumbs.jsonunit.core.util.ResourceUtils
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import strikt.api.expectThat
import strikt.api.expectThrows
import strikt.assertions.isA
import strikt.assertions.isEqualTo
import strikt.assertions.isNotNull
import strikt.assertions.isNull
import strikt.assertions.isTrue
import java.net.InetSocketAddress

internal class BearerTokenReactiveAuthenticationManagerResolverTest {

    private val client: AuthenticationStoreClient = mockk()
    private val auditClient: AuthenticationAuditClient = mockk {
        every { recordLoginSuccess(any(), any(), any(), any(), any()) } returns Mono.empty()
        every { recordLoginFailure(any(), any(), any(), any(), any(), any(), any()) } returns Mono.empty()
    }
    private val exchange: ServerWebExchange = mockk {
        every { request.uri.host } returns HOST
        every { request.remoteAddress } returns InetSocketAddress("127.0.0.1", 8080)
    }

    @Test
    fun `authenticates incorrect token type`() {
        val mockExchange: ServerWebExchange = mockk {
            every { request.uri.host } returns HOST
            every { request.remoteAddress } returns InetSocketAddress("127.0.0.1", 8080)
        }

        val resolver = BearerTokenReactiveAuthenticationManagerResolver(client, auditClient)
        val manager = resolver.resolve(mockExchange).block()!!

        expectThat(
            manager.authenticate(mockk<OAuth2AuthenticationToken>())
                .orgContextWrite(ORGANIZATION)
                .block()
        ) { isNull() }
    }

    @Test
    fun `authenticates incorrect bearer token`() {
        every { client.getUserByApiToken(ORG_ID, "invalid") } returns Mono.error(InvalidBearerTokenException(""))
        val resolver = BearerTokenReactiveAuthenticationManagerResolver(client, auditClient)
        val manager = resolver.resolve(exchange).block()!!

        expectThrows<InvalidBearerTokenException> {
            manager.authenticate(BearerTokenAuthenticationToken("invalid"))
                .orgContextWrite(ORGANIZATION)
                .block()
        }
    }

    @Test
    fun `authenticates valid bearer token`() {
        every { client.getUserByApiToken(ORG_ID, TOKEN) } returns Mono.just(User(USER_ID, usedTokenId = "TheToken"))

        val resolver = BearerTokenReactiveAuthenticationManagerResolver(client, auditClient)
        val manager = resolver.resolve(exchange).block()!!

        val authenticated = manager.authenticate(BearerTokenAuthenticationToken(TOKEN))
            .orgContextWrite(ORGANIZATION)
            .block()

        expectThat(authenticated) {
            isNotNull().get(Authentication::isAuthenticated).isTrue()
            isA<UserContextAuthenticationToken>().and {
                get { user.usedTokenId }.isEqualTo("TheToken")
            }
        }

        verify {
            auditClient.recordLoginSuccess(
                orgId = ORG_ID,
                userId = USER_ID,
                source = "127.0.0.1",
                sessionContextType = AuthMethod.API_TOKEN,
                sessionContextIdentifier = "TheToken",
            )
        }
    }

    @Test
    fun `authenticates valid bearer JWT token`() {
        mockJwks()
        every { client.getUserById(ORG_ID, USER_ID) } returns Mono.just(
            User(USER_ID, usedTokenId = "TheToken")
        )
        every {
            auditClient.recordLoginSuccess(any(), any(), any(), any(), any())
        } returns Mono.empty()

        val resolver = BearerTokenReactiveAuthenticationManagerResolver(client, auditClient)
        val manager = resolver.resolve(exchange).block()!!

        val authenticated = manager.authenticate(
            BearerTokenAuthenticationToken(VALID_JWT)
        ).orgContextWrite(ORGANIZATION).block()
        expectThat(authenticated) {
            isNotNull().get(Authentication::isAuthenticated).isTrue()
        }
    }

    @Test
    fun `authentication fails when no JWK configured for the organization`() {
        mockJwks(emptyList())

        val resolver = BearerTokenReactiveAuthenticationManagerResolver(client, auditClient)
        val manager = resolver.resolve(exchange).block()!!

        expectThrows<JwtVerificationException> {
            manager.authenticate(BearerTokenAuthenticationToken(VALID_JWT)).orgContextWrite(ORGANIZATION).block()
        }.and {
            get { message }.isEqualTo("The JWT contains invalid claims.")
        }
    }

    @Test
    fun `authentication fails for expired JWT`() {
        mockJwks()

        val resolver = BearerTokenReactiveAuthenticationManagerResolver(client, auditClient)
        val manager = resolver.resolve(exchange).block()!!

        expectThrows<JwtExpiredException> {
            manager.authenticate(BearerTokenAuthenticationToken(EXPIRED_JWT))
                .orgContextWrite(ORGANIZATION)
                .block()
        }.and {
            get { message }.isEqualTo("The JWT is expired.")
        }
    }

    @Test
    fun `authentication fails for non-matching private key alg with JWT`() {
        mockJwks()

        val resolver = BearerTokenReactiveAuthenticationManagerResolver(client, auditClient)
        val manager = resolver.resolve(exchange).block()!!

        val invalidJwt = ResourceUtils.resource("jwt/jwt_non_matching_alg.txt").readText()
        expectThrows<JwtVerificationException> {
            manager.authenticate(BearerTokenAuthenticationToken(invalidJwt))
                .orgContextWrite(ORGANIZATION)
                .block()
        }.and {
            get { message }.isEqualTo("The JWT contains invalid claims.")
        }
    }

    @Test
    fun `authentication fails for non-matching public key`() {
        mockOrganization(client, HOST, Organization(ORG_ID))
        mockJwks()

        val resolver = BearerTokenReactiveAuthenticationManagerResolver(client, auditClient)
        val manager = resolver.resolve(exchange).block()!!

        val invalidJwt = ResourceUtils.resource("jwt/jwt_non_matching_key.txt").readText()
        expectThrows<JwtSignatureException> {
            manager.authenticate(BearerTokenAuthenticationToken(invalidJwt))
                .orgContextWrite(ORGANIZATION)
                .block()
        }.and {
            get { message }.isEqualTo("We are unable to verify signature.")
        }
    }

    @ParameterizedTest
    @ValueSource(strings = ["jku", "x5u", "jwk", "x5c"])
    fun `authentication fails for JWT with invalid fields`(parameterName: String) {
        mockJwks()

        val resolver = BearerTokenReactiveAuthenticationManagerResolver(client, auditClient)
        val manager = resolver.resolve(exchange).block()!!

        val invalidJwt = ResourceUtils.resource("jwt/jwt_invalid_par_$parameterName.txt").readText()

        expectThrows<JwtVerificationException> {
            manager.authenticate(BearerTokenAuthenticationToken(invalidJwt)).orgContextWrite(ORGANIZATION).block()
        }.and {
            get { message }.isEqualTo("The JWT contains invalid claims.")
        }
    }

    @ParameterizedTest
    @ValueSource(strings = ["name", "sub", "jti"])
    fun `authentication fails for JWT with invalid fields pattern`(parameterName: String) {
        mockOrganization(client, HOST, Organization(ORG_ID))
        mockJwks()

        val resolver = BearerTokenReactiveAuthenticationManagerResolver(client, auditClient)
        val manager = resolver.resolve(exchange).block()!!

        val invalidJwt = ResourceUtils.resource("jwt/jwt_invalid_$parameterName.txt").readText()

        expectThrows<JwtVerificationException> {
            manager.authenticate(BearerTokenAuthenticationToken(invalidJwt))
                .orgContextWrite(ORGANIZATION)
                .block()
        }.and {
            get { message }.isEqualTo("The JWT contains invalid claims.")
        }
    }

    @ParameterizedTest
    @ValueSource(strings = ["jwt_invalid_type.txt", "jwt_missing_kid_header.txt"])
    fun `test auth failed for invalid header`(jwtSourceFile: String) {
        mockJwks()

        val resolver = BearerTokenReactiveAuthenticationManagerResolver(client, auditClient)
        val manager = resolver.resolve(exchange).block()!!

        val invalidJwt = ResourceUtils.resource("jwt/$jwtSourceFile").readText()

        expectThrows<JwtVerificationException> {
            manager.authenticate(BearerTokenAuthenticationToken(invalidJwt)).orgContextWrite(ORGANIZATION).block()
        }.and {
            get { message }.isEqualTo("The JWT contains invalid claims.")
        }
    }

    @ParameterizedTest
    @ValueSource(strings = ["iat", "exp", "sub", "iat_and_exp"])
    fun `test auth failed for missing mandatory attribute`(attribute: String) {
        mockJwks()

        val resolver = BearerTokenReactiveAuthenticationManagerResolver(client, auditClient)
        val manager = resolver.resolve(exchange).orgContextWrite(ORGANIZATION).block()!!

        val invalidJwt = ResourceUtils.resource("jwt/jwt_missing_${attribute}_attr.txt").readText()
        expectThrows<JwtVerificationException> {
            manager.authenticate(BearerTokenAuthenticationToken(invalidJwt)).orgContextWrite(ORGANIZATION).block()
        }.and {
            val invalidClaims = attribute.split("_and_")
            get { message }.isEqualTo(JwtVerificationException.invalidClaimsMessage(invalidClaims))
        }
    }

    @Test
    fun `test auth failed if unable to decode JWT`() {
        mockJwks()

        val resolver = BearerTokenReactiveAuthenticationManagerResolver(client, auditClient)
        val manager = resolver.resolve(exchange).block()!!

        expectThrows<JwtDecodeException> {
            manager.authenticate(BearerTokenAuthenticationToken("djgAM4sk4.kso1SRmcf.12Kkcml0"))
                .orgContextWrite(ORGANIZATION)
                .block()
        }.and {
            get { message }.isEqualTo("We are unable to decode JWT.")
        }
    }

    private fun mockJwks(jwks: List<JWK> = buildJwks()) {
        every { client.getJwks(ORG_ID) } returns Mono.just(jwks)
    }

    private fun buildJwks() = listOf(buildJwk(PUBLIC_KEY))

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
        val useAs: KeyUse = KeyUse.SIGNATURE,
    )

    companion object {
        private const val HOST = "localhost"
        private const val ORG_ID = "organizationId"
        private const val USER_ID = "demo.key001"
        private const val TOKEN = "ZGVtbzpUaGVUb2tlbjpidGVSSG0zYjJqaWtiVUNwZlJ5eTVLSXNiRXhiMHpqSA=="
        private const val PUBLIC_KEY_ID = "kid001_rs256"

        private val PUBLIC_KEY_VALUE = ResourceUtils.resource("jwt/jwk_public_key.txt").readText()
        private val PUBLIC_KEY = PublicKey(PUBLIC_KEY_ID, PUBLIC_KEY_VALUE)

        private val VALID_JWT = ResourceUtils.resource("jwt/jwt_valid.txt").readText()
        private val EXPIRED_JWT = ResourceUtils.resource("jwt/jwt_expired.txt").readText()
        private val ORGANIZATION = Organization(ORG_ID)
    }
}

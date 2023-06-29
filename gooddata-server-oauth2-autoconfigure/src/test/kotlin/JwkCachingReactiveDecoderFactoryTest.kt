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

import com.nimbusds.jose.jwk.JWKSet
import io.mockk.every
import io.mockk.impl.annotations.MockK
import io.mockk.junit5.MockKExtension
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.core.AuthenticationMethod
import org.springframework.security.oauth2.core.AuthorizationGrantType
import strikt.api.expectThat
import strikt.assertions.isNotSameInstanceAs

@ExtendWith(MockKExtension::class)
internal class JwkCachingReactiveDecoderFactoryTest {

    @MockK
    private lateinit var jwkCache: JwkCache

    @Test
    fun `creates new instance every time`() {
        every { jwkCache.get(any(), any()) } returns JWKSet()
        val factory = JwkCachingReactiveDecoderFactory(jwkCache)
        val registration = ClientRegistration.withRegistrationId("id")
            .clientId("clientId")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
            .authorizationUri("authorizationUri")
            .tokenUri("tokenUri")
            .userInfoUri("userInfoUri")
            .userInfoAuthenticationMethod(AuthenticationMethod("header"))
            .jwkSetUri("http://localhost")
            .build()

        expectThat(factory.createDecoder(registration)).isNotSameInstanceAs(factory.createDecoder(registration))
    }
}

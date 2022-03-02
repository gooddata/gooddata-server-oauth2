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
package com.gooddata.oauth2.server.servlet

import com.gooddata.oauth2.server.common.JwkCache
import com.gooddata.oauth2.server.common.SimpleRemoteJwkSource
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtDecoderFactory
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder

/**
 * [JwkCachingDecoderFactory.createDecoder] creates everytime new instance of [NimbusJwtDecoder] to avoid any underlying
 * caching. Caching is done using external [JwkCache].
 *
 * Spring Security is designed for static definition of clients in properties but we need to define them dynamically
 * in runtime and be able to change their configuration. To connect which request needs which configuration we use
 * hostname that is used as registration ID.
 *
 * Original [OidcIdTokenDecoderFactory], that is used by default by Spring Security and internally in this
 * implementation, caches decoders created in [OidcIdTokenDecoderFactory.createDecoder] in private map under
 * [ClientRegistration.getRegistrationId]. When [ClientRegistration] is updated (new with same registration ID is
 * created) the old properties are used and newly created tokens cannot be decoded.
 * As [OidcIdTokenDecoderFactory] is final class and it was not intended to copy its logic out
 * the [JwkCachingDecoderFactory] simply creates new instance of [NimbusJwtDecoder] every time and setup it as
 * [OidcIdTokenDecoderFactory] does with additional caching using external [JwkCache].
 * @param[jwkCache] JWK cache
 * @param[jwtValidatorFactory] JWT validator factory. Default is used when null.
 */
class JwkCachingDecoderFactory(
    private val jwkCache: JwkCache,
    private val jwtValidatorFactory: ((ClientRegistration) -> OAuth2TokenValidator<Jwt>)? = null
) : JwtDecoderFactory<ClientRegistration> {

    /**
     * Creates a new [OidcIdTokenDecoderFactory] using the supplied [ClientRegistration].
     *
     * @param context [ClientRegistration] for which the decoder is to be created
     * @return a [JwtDecoder]
     */
    override fun createDecoder(context: ClientRegistration): JwtDecoder {
        val jwkSetUri = context.providerDetails.jwkSetUri

        return NimbusJwtDecoder(processor(jwkSetUri)).apply {
            jwtValidatorFactory?.let { setJwtValidator(it(context)) }
        }
    }

    private fun processor(jwkSetUri: String) =
        DefaultJWTProcessor<SecurityContext>().apply {
            jwsKeySelector = JWSVerificationKeySelector(
                JWSAlgorithm.RS256,
                SimpleRemoteJwkSource(
                    jwkSetUri = jwkSetUri,
                    jwkCache = jwkCache
                )
            )
        }
}

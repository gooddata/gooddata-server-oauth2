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

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.proc.BadJWTException
import org.springframework.security.oauth2.client.oidc.authentication.ReactiveOidcIdTokenDecoderFactory
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoderFactory
import org.springframework.web.client.RestOperations
import org.springframework.web.client.RestTemplate
import reactor.core.publisher.Mono
import reactor.kotlin.core.publisher.toMono

/**
 * [JwkCachingReactiveDecoderFactory.createDecoder] creates everytime new instance of [NimbusReactiveJwtDecoder]
 * to avoid any underlying caching like [ReactiveOidcIdTokenDecoderFactory] does from which logic was taken. It was
 * added JWK caching using [JwkCache] to improve performance by reducing JWK calls.
 *
 * Spring Security is designed for static definition of clients in properties but we need to define them dynamically
 * in runtime and be able to change their configuration. To connect which request needs which configuration we use
 * hostname that is used as registration ID.
 *
 * Original [ReactiveOidcIdTokenDecoderFactory], that is used by default by Spring Security and internally in this
 * implementation, caches decoders created in [ReactiveOidcIdTokenDecoderFactory.createDecoder] in private map under
 * [ClientRegistration.getRegistrationId]. When [ClientRegistration] is updated (new with same registration ID is
 * created) the old properties are used and newly created tokens cannot be decoded.
 * As [ReactiveOidcIdTokenDecoderFactory] is final class and it was not intended to copy its logic out
 * the [JwkCachingReactiveDecoderFactory] simply creates new instance of [NimbusReactiveJwtDecoder] every time
 * ans JWKs are cached to improve performance.
 * @param[jwkCache] JWK cache
 * @param[jwtValidatorFactory] JWT validator factory. Default is used when null.
 */
class JwkCachingReactiveDecoderFactory(
    private val jwkCache: JwkCache,
    private val jwtValidatorFactory: ((ClientRegistration) -> OAuth2TokenValidator<Jwt>)? = null,
    private val restOperations: RestOperations = RestTemplate(),
) : ReactiveJwtDecoderFactory<ClientRegistration> {

    /**
     * Creates a new [ReactiveOidcIdTokenDecoderFactory] using the supplied [ClientRegistration].
     *
     * @param context [ClientRegistration] for which the decoder is to be created
     * @return a [ReactiveJwtDecoder]
     */
    override fun createDecoder(context: ClientRegistration?): ReactiveJwtDecoder {
        val jwkSetUri = context!!.providerDetails.jwkSetUri

        return prepareJwtDecoder(getJwkSet(jwkSetUri), setOf(JWSAlgorithm.RS256)).apply {
            if (jwtValidatorFactory != null) {
                setJwtValidator(jwtValidatorFactory.invoke(context))
            }
        }
    }

    private fun getJwkSet(jwkSetUri: String): Mono<JWKSet> = SimpleRemoteJwkSource(
        restOperations = restOperations,
        jwkSetUri = jwkSetUri,
        jwkCache = jwkCache,
    ).get().toMono()
}

/**
 * Signalizes that the JWT token is expired = its `exp` time is not valid anymore.
 */
internal class InternalJwtExpiredException(subject: String? = null) : BadJWTException("JWT $subject has expired.")

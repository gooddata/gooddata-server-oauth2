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

import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtDecoderFactory

/**
 * [JwtDecoderFactory] that wraps [OidcIdTokenDecoderFactory] and delegates every
 * [NoCachingDecoderFactory.createDecoder] to new instance to avoid any underlying caching.
 *
 * Spring Security is designed for static definition of clients in properties but we need to define them dynamically
 * in runtime and be able to change their configuration. To connect which request needs which configuration we use
 * hostname that is used as registration ID.
 *
 * Wrapped [OidcIdTokenDecoderFactory], that is used by default by Spring Security and internally in this
 * implementation, caches decoders created in [OidcIdTokenDecoderFactory.createDecoder] in private map under
 * [ClientRegistration.getRegistrationId]. When [ClientRegistration] is updated (new with same registration ID is
 * created) the old properties are used and newly created tokens cannot be decoded.
 * As [OidcIdTokenDecoderFactory] is final class and it was not intended to copy its logic out
 * the [NoCachingDecoderFactory] simply creates new instance of [OidcIdTokenDecoderFactory] every time.
 */
class NoCachingDecoderFactory : JwtDecoderFactory<ClientRegistration> {

    var jwtValidatorFactory: ((ClientRegistration) -> OAuth2TokenValidator<Jwt>)? = null

    /**
     * Creates a new [OidcIdTokenDecoderFactory] using the supplied [ClientRegistration].
     *
     * @param context [ClientRegistration] for which the decoder is to be created
     * @return a [JwtDecoder]
     */
    override fun createDecoder(context: ClientRegistration?): JwtDecoder =
        OidcIdTokenDecoderFactory()
            .apply {
                if (jwtValidatorFactory != null) {
                    this.setJwtValidatorFactory(jwtValidatorFactory)
                }
            }.createDecoder(context)
}

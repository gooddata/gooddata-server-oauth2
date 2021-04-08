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

import com.gooddata.oauth2.server.common.SPRING_SEC_SECURITY_CONTEXT
import com.gooddata.oauth2.server.common.jackson.mapper
import mu.KotlinLogging
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.oauth2.jwt.JwtDecoderFactory
import org.springframework.security.oauth2.jwt.JwtException
import org.springframework.security.web.context.HttpRequestResponseHolder
import org.springframework.security.web.context.SecurityContextRepository
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * [SecurityContextRepository] implementation that stores [SecurityContext] information into
 * `SPRING_SEC_SECURITY_CONTEXT` HTTP cookie. Security context is not stored as a whole but only JWT part of OAuth2
 * ID token together with some additional necessary information. This is in contrast to default
 * [org.springframework.security.web.context.HttpSessionSecurityContextRepository] that uses HTTP sessions.
 */
class CookieSecurityContextRepository(
    private val clientRegistrationRepository: ClientRegistrationRepository,
    private val cookieService: CookieService,
    private val jwtDecoderFactory: JwtDecoderFactory<ClientRegistration> =
        NoCachingDecoderFactory().apply {
            // ID token and its expiration is not validated in WebSessionServerSecurityContextRepository neither
            jwtValidatorFactory = { OAuth2TokenValidator { OAuth2TokenValidatorResult.success() } }
        },
) : SecurityContextRepository {

    private val logger = KotlinLogging.logger {}

    @Suppress("ReturnCount")
    override fun loadContext(requestResponseHolder: HttpRequestResponseHolder): SecurityContext {
        val decoded = cookieService.decodeCookie(
            requestResponseHolder.request,
            SPRING_SEC_SECURITY_CONTEXT,
            mapper,
            OAuth2AuthenticationToken::class.java
        ) ?: return SecurityContextHolder.createEmptyContext()

        // find registration based on its ID
        val registration = clientRegistrationRepository.findByRegistrationId(decoded.authorizedClientRegistrationId)
            ?: return SecurityContextHolder.createEmptyContext()
        val jwt = try {
            jwtDecoderFactory.createDecoder(registration)
                // decode JWT token from JSON
                .decode((decoded.principal as OidcUser).idToken.tokenValue)
        } catch (e: JwtException) {
            logger.info(e) { "Stored JWT token cannot be decoded" }
            return SecurityContextHolder.createEmptyContext()
        }
        val oidc = OidcIdToken(jwt.tokenValue, jwt.issuedAt, jwt.expiresAt, jwt.claims)
        val token = OAuth2AuthenticationToken(
            DefaultOidcUser(
                decoded.principal.authorities,
                oidc,
                registration.providerDetails.userInfoEndpoint.userNameAttributeName
            ),
            emptyList(), // it is not stored in JSON anyway
            registration.registrationId
        )

        return SecurityContextImpl(token)
    }

    override fun saveContext(context: SecurityContext, request: HttpServletRequest, response: HttpServletResponse) {
        if (context.authentication !is OAuth2AuthenticationToken || context.authentication.principal !is OidcUser) {
            cookieService.invalidateCookie(request, response, SPRING_SEC_SECURITY_CONTEXT)
        } else {
            cookieService.createCookie(
                request, response, SPRING_SEC_SECURITY_CONTEXT, mapper.writeValueAsString(context.authentication)
            )
        }
    }

    override fun containsContext(request: HttpServletRequest): Boolean {
        return cookieService.decodeCookie(
            request,
            SPRING_SEC_SECURITY_CONTEXT,
            mapper,
            OAuth2AuthenticationToken::class.java
        ) != null
    }
}

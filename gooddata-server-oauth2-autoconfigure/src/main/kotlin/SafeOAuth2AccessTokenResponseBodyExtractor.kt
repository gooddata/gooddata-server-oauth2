/*
 * (C) 2022 GoodData Corporation
 */
package com.gooddata.oauth2.server

import com.gooddata.oauth2.server.common.removeIllegalCharacters
import com.nimbusds.oauth2.sdk.AccessTokenResponse
import com.nimbusds.oauth2.sdk.ErrorObject
import com.nimbusds.oauth2.sdk.ParseException
import com.nimbusds.oauth2.sdk.TokenErrorResponse
import com.nimbusds.oauth2.sdk.TokenResponse
import net.minidev.json.JSONObject
import org.springframework.core.ParameterizedTypeReference
import org.springframework.http.ReactiveHttpInputMessage
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.OAuth2AuthorizationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse
import org.springframework.web.reactive.function.BodyExtractor
import org.springframework.web.reactive.function.BodyExtractors
import reactor.core.publisher.Mono

/**
 * Original:
 * [org.springframework.security.oauth2.core.web.reactive.function.OAuth2AccessTokenResponseBodyExtractor]
 */
class SafeOAuth2AccessTokenResponseBodyExtractor :
    BodyExtractor<Mono<OAuth2AccessTokenResponse>, ReactiveHttpInputMessage> {

    override fun extract(
        inputMessage: ReactiveHttpInputMessage,
        context: BodyExtractor.Context
    ): Mono<OAuth2AccessTokenResponse> =
        BodyExtractors.toMono(STRING_OBJECT_MAP)
            .extract(inputMessage, context)
            .onErrorMap { exception: Throwable ->
                OAuth2AuthorizationException(
                    invalidTokenResponse("An error occurred parsing the Access Token response: " + exception.message),
                    exception
                )
            }
            .switchIfEmpty(
                Mono.error {
                    OAuth2AuthorizationException(invalidTokenResponse("Empty OAuth 2.0 Access Token Response"))
                }
            )
            .map(::correct)
            .map(::parse)
            .flatMap(::oauth2AccessTokenResponse)
            .map(::oauth2AccessTokenResponse)

    companion object {
        private val KEYS_TO_CORRECT = listOf("error", "error_description", "error_uri")

        private const val INVALID_TOKEN_RESPONSE_ERROR_CODE = "invalid_token_response"

        private val STRING_OBJECT_MAP: ParameterizedTypeReference<Map<String, Any>> =
            object : ParameterizedTypeReference<Map<String, Any>>() {}

        private fun correct(json: Map<String, Any>): Map<String, Any> =
            json.entries.associate { entry ->
                val value = entry.value
                entry.key to if (entry.key in KEYS_TO_CORRECT && value is String) {
                    value.removeIllegalCharacters()
                } else {
                    value
                }
            }

        private fun parse(json: Map<String, Any>): TokenResponse =
            try {
                TokenResponse.parse(JSONObject(json))
            } catch (ex: ParseException) {
                val oauth2Error = invalidTokenResponse(
                    "An error occurred parsing the Access Token response: " + ex.message
                )
                throw OAuth2AuthorizationException(oauth2Error, ex)
            }

        private fun invalidTokenResponse(message: String): OAuth2Error =
            OAuth2Error(INVALID_TOKEN_RESPONSE_ERROR_CODE, message, null)

        private fun oauth2AccessTokenResponse(tokenResponse: TokenResponse): Mono<AccessTokenResponse> =
            if (tokenResponse.indicatesSuccess()) {
                Mono.just(tokenResponse).cast(AccessTokenResponse::class.java)
            } else {
                val tokenErrorResponse = tokenResponse as TokenErrorResponse
                val oauth2Error = getOAuth2Error(tokenErrorResponse.errorObject)
                Mono.error(OAuth2AuthorizationException(oauth2Error))
            }

        private fun getOAuth2Error(errorObject: ErrorObject?): OAuth2Error =
            if (errorObject == null) {
                OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR)
            } else {
                val code = errorObject.code ?: OAuth2ErrorCodes.SERVER_ERROR
                val description = errorObject.description
                val uri = errorObject.uri?.toString()
                OAuth2Error(code, description, uri)
            }

        private fun oauth2AccessTokenResponse(accessTokenResponse: AccessTokenResponse): OAuth2AccessTokenResponse {
            val accessToken = accessTokenResponse.tokens.accessToken
            val accessTokenType =
                if (OAuth2AccessToken.TokenType.BEARER.value.equals(accessToken.type.value, ignoreCase = true)) {
                    OAuth2AccessToken.TokenType.BEARER
                } else {
                    null
                }
            val expiresIn = accessToken.lifetime
            val scopes = accessToken.scope?.toStringList()?.toSet() ?: emptySet()
            val refreshToken = accessTokenResponse.tokens.refreshToken?.value
            val additionalParameters: Map<String, Any> = LinkedHashMap(accessTokenResponse.customParameters)

            return OAuth2AccessTokenResponse.withToken(accessToken.value)
                .tokenType(accessTokenType)
                .expiresIn(expiresIn)
                .scopes(scopes)
                .refreshToken(refreshToken)
                .additionalParameters(additionalParameters)
                .build()
        }
    }
}

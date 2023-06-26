package com.gooddata.oauth2.server

import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult
import org.springframework.security.oauth2.jwt.Jwt

class CustomOAuth2Validator : OAuth2TokenValidator<Jwt> {

    companion object {
        // These headers are potential security vulnerabilities for header injection
        val notAllowedHeaders = listOf("jku", "x5u", "jwk", "x5c")
    }

    override fun validate(token: Jwt): OAuth2TokenValidatorResult {
        val validationErrors = mutableListOf<OAuth2Error>()
        notAllowedHeaders.forEach { header ->
            if (token.headers.containsKey(header)) {
                validationErrors.add(
                    OAuth2Error(
                        "${header}_not_allowed",
                        "Jwt contains not allowed header parameter \"${header}\".",
                        null
                    )
                )
            }
        }
        return if (validationErrors.isEmpty()) OAuth2TokenValidatorResult.success()
        else OAuth2TokenValidatorResult.failure(validationErrors)
    }
}

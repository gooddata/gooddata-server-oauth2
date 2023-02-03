/*
 * Copyright 2022 GoodData Corporation
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

import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes

/**
 * Thrown when an error during cookie decoding occurs. Typically, of token expiration.
 *
 * The exception is descendant of [OAuth2AuthenticationException] which represents the "Bearer" authentication error
 * which is handled when the cookie is not properly decoded. We can also say that any of cookies represents part
 * of the "Bearer" OAuth2 token.
 *
 * @param[message] exception message
 * @param[cause] exception cause
 *
 * @see OAuth2AuthenticationException
 */
class CookieDecodeException(message: String?, cause: Throwable? = null) : OAuth2AuthenticationException(
    OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, message, null),
    message,
    cause,
)

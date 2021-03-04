/*
 * Copyright 2002-2020 the original author or authors.
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
 *
 * Forked from https://github.com/spring-projects/spring-security/blob/5.4.0/oauth2/oauth2-client/src/main/java/org/springframework/security/oauth2/client/jackson2/OAuth2AccessTokenMixin.java
 */
package com.gooddata.oauth2.server.jackson

import com.fasterxml.jackson.annotation.JsonAutoDetect
import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonTypeInfo
import com.fasterxml.jackson.databind.annotation.JsonDeserialize
import org.springframework.security.oauth2.core.OAuth2AccessToken
import java.time.Instant

/**
 * This mixin class is used to serialize/deserialize [OAuth2AccessToken].
 *
 * @author Joe Grandja
 * @since 5.3
 * @see OAuth2AccessToken
 *
 * @see OAuth2ClientJackson2Module
 */
@Suppress("UNUSED_PARAMETER")
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonAutoDetect(
    fieldVisibility = JsonAutoDetect.Visibility.ANY,
    getterVisibility = JsonAutoDetect.Visibility.NONE,
    isGetterVisibility = JsonAutoDetect.Visibility.NONE
)
@JsonIgnoreProperties(ignoreUnknown = true)
internal abstract class OAuth2AccessTokenMixin @JsonCreator constructor(
    @JsonProperty("tokenType") @JsonDeserialize(converter = StdConverters.AccessTokenTypeConverter::class)
    tokenType: OAuth2AccessToken.TokenType?,
    @JsonProperty("tokenValue")
    tokenValue: String?,
    @JsonProperty("issuedAt")
    issuedAt: Instant?,
    @JsonProperty("expiresAt")
    expiresAt: Instant?,
    @JsonProperty("scopes")
    scopes: Set<String?>?
)

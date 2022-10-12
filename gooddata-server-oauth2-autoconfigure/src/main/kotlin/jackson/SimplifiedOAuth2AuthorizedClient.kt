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
package com.gooddata.oauth2.server.jackson

import com.fasterxml.jackson.annotation.JsonAutoDetect
import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.OAuth2RefreshToken

/**
 * Simplified representation of [OAuth2AuthorizedClient].
 *
 * @see OAuth2AuthorizedClient
 */
@JsonAutoDetect(
    fieldVisibility = JsonAutoDetect.Visibility.ANY,
    getterVisibility = JsonAutoDetect.Visibility.NONE,
    isGetterVisibility = JsonAutoDetect.Visibility.NONE
)
@JsonIgnoreProperties(ignoreUnknown = true)
class SimplifiedOAuth2AuthorizedClient @JsonCreator constructor(
    @JsonProperty("registrationId") val registrationId: String,
    @JsonProperty("principalName") val principalName: String,
    @JsonProperty("accessToken") val accessToken: OAuth2AccessToken,
    @JsonProperty("refreshToken") val refreshToken: OAuth2RefreshToken?
)

fun OAuth2AuthorizedClient.toSimplified(): SimplifiedOAuth2AuthorizedClient =
    SimplifiedOAuth2AuthorizedClient(
        clientRegistration.registrationId,
        principalName,
        accessToken,
        refreshToken
    )

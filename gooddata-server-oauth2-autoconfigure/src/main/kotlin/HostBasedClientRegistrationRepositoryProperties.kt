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

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.bind.DefaultValue

@ConfigurationProperties(prefix = "spring.security.oauth2.client.repository")
class HostBasedClientRegistrationRepositoryProperties(
    /**
     * Address of the built in OIDC provider that is accessible from user's web browser.
     */
    @DefaultValue("http://localhost:3000")
    val remoteAddress: String,

    /**
     * Address of the built in OIDC provider that is accessible from services that use this starter.
     */
    @DefaultValue("http://dex:5556")
    val localAddress: String
)

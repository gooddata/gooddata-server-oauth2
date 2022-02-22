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
package com.gooddata.oauth2.server.common

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.ConstructorBinding
import org.springframework.boot.context.properties.bind.DefaultValue
import java.net.URI

@ConstructorBinding
@ConfigurationProperties(prefix = "spring.security.oauth2.client.applogin")
class AppLoginProperties(
    /**
     * Defines which hostnames are allowed to be used in `redirectTo` param on `/appLogin` resource. When empty value is
     * used it means that only relative URIs are allowed in `redirectTo`. If hostname is set to some schema+host+port
     * (e.g. http://localhost:3000) then request can be redirected there.
     *
     * Defaults to empty string.
     */
    @DefaultValue("")
    val allowRedirect: URI,
)

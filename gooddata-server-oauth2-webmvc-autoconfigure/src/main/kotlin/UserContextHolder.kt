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

/**
 * Interface defining contract for storing and clearing current authenticated user context. Client is responsible for
 * the creation of any data structure it feels appropriate and choose proper context storage.
 */
interface UserContextHolder {

    /**
     * Sets and stores provided information as a new authenticated user context.
     */
    fun setContext(organizationId: String, userId: String, userName: String?)

    /**
     * Clears currently authenticated user context.
     */
    fun clearContext()
}

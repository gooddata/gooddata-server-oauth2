/*
 * Copyright 2024 GoodData Corporation
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

import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Test
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.web.server.ResponseStatusException
import strikt.api.expectThat
import strikt.api.expectThrows
import strikt.assertions.isEqualTo
import strikt.assertions.isNotNull

class OAuth2UserValidatorTest {

    private val userValidator = OAuth2UserValidator()
    private val userRequest = mockk<OAuth2UserRequest> {
        every { clientRegistration } returns mockk {
            every { providerDetails } returns mockk {
                every { userInfoEndpoint } returns mockk {
                    every { userNameAttributeName } returns "userName"
                }
            }
        }
    }

    @Test
    fun `should raise exception when user does not contain valid user name claim`() {
        // given
        val user = mockk<OAuth2User> {
            every { attributes } returns mapOf("userName" to "")
        }

        // then
        expectThrows<ResponseStatusException> {
            userValidator.validateUser(userRequest, user).block()
        }.and {
            get { message }.isEqualTo(
                "401 UNAUTHORIZED \"Authorization failed, \"user name\" attribute - userName contains invalid " +
                    "value! Please check your Client Registration settings.\""
            )
        }
    }

    @Test
    fun `user should pass validation with valid userName attribute`() {
        // given
        val user = mockk<OAuth2User> {
            every { attributes } returns mapOf("userName" to "Admin GoodData")
        }

        // then
        expectThat(userValidator.validateUser(userRequest, user).block()) {
            isNotNull().and { isEqualTo(user) }
        }
    }
}

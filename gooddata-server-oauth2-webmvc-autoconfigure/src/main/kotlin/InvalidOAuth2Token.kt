/*
 * Copyright (C) 2007-2022, GoodData(R) Corporation. All rights reserved.
 */

package com.gooddata.oauth2.server.servlet

import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.authority.AuthorityUtils

/**
 * The representation of the invalid OAuth2 token which tells why the token was not valid.
 *
 * @param errorType the machine-readable code for the invalid token processing
 * @param errorMessage the reason message why the token was not valid
 */
class InvalidOAuth2Token(
    val errorType: String,
    val errorMessage: String,
) : AbstractAuthenticationToken(AuthorityUtils.NO_AUTHORITIES) {
    override fun getCredentials() = null

    override fun getPrincipal() = null

    override fun isAuthenticated() = false

    override fun setAuthenticated(authenticated: Boolean) {
        require(!authenticated) { "The invalid OAuth2 token cannot be set to 'trusted'" }
    }
}

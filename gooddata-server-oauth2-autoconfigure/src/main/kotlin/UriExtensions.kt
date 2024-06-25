/*
 * (C) 2022 GoodData Corporation
 */
package com.gooddata.oauth2.server

import org.springframework.web.util.UriComponentsBuilder
import java.net.URI

/**
 * Build URI from string
 */
fun String.toUri(): URI = UriComponentsBuilder.fromUriString(this).build().toUri()

/**
 * Trim URI to base
 */
fun URI.baseUrl(): URI = UriComponentsBuilder.newInstance().scheme(scheme).host(host).port(port).build().toUri()

/**
 * Check if URI is Auth0 issuer
 */
fun URI.isAuth0(): Boolean = host?.lowercase()?.endsWith("auth0.com") ?: false

/**
 * Check if URI is Cognito issuer
 */
fun URI.isCognito(): Boolean {
    val lowerCasedHost = host?.lowercase() ?: return false
    return lowerCasedHost.endsWith("amazonaws.com") && lowerCasedHost.startsWith("cognito-idp")
}

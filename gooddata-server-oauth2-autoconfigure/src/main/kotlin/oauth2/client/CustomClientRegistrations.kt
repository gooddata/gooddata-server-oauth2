/*
 * Copyright 2002-2024 the original author or authors.
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
 *
 * Forked from https://github.com/spring-projects/spring-security/blob/6.4.0-RC1/oauth2/oauth2-client/src/main/java/org/springframework/security/oauth2/client/registration/ClientRegistrations.java
 *
 * The fromOidcConfiguration factory method (and necessary helper functions) has been extracted from the original class
 * for immediate use until the Spring Security stable version containing it is released.
 *
 * This class and its methods are subject to removal once the Spring Security stable version containing the
 * fromOidcConfiguration factory method is released and the dependency in the project is updated.
 */
package com.gooddata.oauth2.server.oauth2.client

import com.gooddata.oauth2.server.parse
import com.nimbusds.oauth2.sdk.`as`.AuthorizationServerMetadata
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames
import org.springframework.util.Assert
import java.net.URI

/**
 * Creates a {@link ClientRegistration.Builder} using the provided map representation
 * of an <a href=
 * "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse">OpenID
 * Provider Configuration Response</a> to initialize the
 * {@link ClientRegistration.Builder}.
 *
 * <p>
 * This is useful when the OpenID Provider Configuration is not available at a
 * well-known location, or if custom validation is needed for the issuer location
 * (e.g. if the issuer is only accessible from a back-channel URI that is different
 * from the issuer value in the configuration).
 * </p>
 *
 * <p>
 * Example usage:
 * </p>
 * <pre>
 * RequestEntity&lt;Void&gt; request = RequestEntity.get(metadataEndpoint).build();
 * ParameterizedTypeReference&lt;Map&lt;String, Object&gt;&gt; typeReference =
 * new ParameterizedTypeReference&lt;&gt;() {};
 * Map&lt;String, Object&gt; configuration = rest.exchange(request, typeReference).getBody();
 * // Validate configuration.get("issuer") as per in the OIDC specification
 * ClientRegistration registration = ClientRegistrations.fromOidcConfiguration(configuration)
 *     .clientId("client-id")
 *     .clientSecret("client-secret")
 *     .build();
 * </pre>
 * @param the OpenID Provider configuration map
 * @return the {@link ClientRegistration} built from the configuration
 */
fun fromOidcConfiguration(configuration: Map<String, Any>): ClientRegistration.Builder {
    val metadata: OIDCProviderMetadata = parse(configuration, OIDCProviderMetadata::parse)
    val builder: ClientRegistration.Builder = withProviderConfiguration(metadata, metadata.issuer.value)
    builder.jwkSetUri(metadata.jwkSetURI.toASCIIString())
    if (metadata.userInfoEndpointURI != null) {
        builder.userInfoUri(metadata.userInfoEndpointURI.toASCIIString())
    }
    return builder
}

private fun withProviderConfiguration(
    metadata: AuthorizationServerMetadata,
    issuer: String
): ClientRegistration.Builder {
    val metadataIssuer: String = metadata.issuer.value
    Assert.state(issuer == metadataIssuer) {
        "The Issuer \"$metadataIssuer\" provided in the configuration metadata did " +
            "not match the requested issuer \"$issuer\""
    }
    val name: String = URI.create(issuer).host
    val method: ClientAuthenticationMethod? = getClientAuthenticationMethod(metadata.tokenEndpointAuthMethods)
    val configurationMetadata: Map<String, Any> = LinkedHashMap(metadata.toJSONObject())

    return ClientRegistration.withRegistrationId(name)
        .userNameAttributeName(IdTokenClaimNames.SUB)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .clientAuthenticationMethod(method)
        .redirectUri("{baseUrl}/{action}/oauth2/code/{registrationId}")
        .authorizationUri(metadata.authorizationEndpointURI?.toASCIIString())
        .providerConfigurationMetadata(configurationMetadata)
        .tokenUri(metadata.tokenEndpointURI.toASCIIString())
        .issuerUri(issuer)
        .clientName(issuer)
}

private fun getClientAuthenticationMethod(
    metadataAuthMethods: List<com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod>?
): ClientAuthenticationMethod? {
    if (metadataAuthMethods == null || metadataAuthMethods
            .contains(com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
    ) {
        // If null, the default includes client_secret_basic
        return ClientAuthenticationMethod.CLIENT_SECRET_BASIC
    }
    if (metadataAuthMethods.contains(com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_POST)) {
        ClientAuthenticationMethod.CLIENT_SECRET_POST
    }
    if (metadataAuthMethods.contains(com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.NONE)) {
        ClientAuthenticationMethod.NONE
    }
    return null
}

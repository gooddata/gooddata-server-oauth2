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

import com.gooddata.oauth2.server.OAuthConstants.GD_USER_GROUPS_SCOPE
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.JWKSecurityContextJWKSet
import com.nimbusds.jose.proc.JWKSecurityContext
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimNames
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.BadJWTException
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier
import com.nimbusds.oauth2.sdk.Scope
import com.nimbusds.openid.connect.sdk.OIDCScopeValue
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import java.security.MessageDigest
import java.time.Instant
import kotlinx.coroutines.reactor.mono
import net.minidev.json.JSONObject
import org.springframework.core.convert.ConversionService
import org.springframework.core.convert.TypeDescriptor
import org.springframework.core.convert.converter.Converter
import org.springframework.http.HttpStatus
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ClientRegistrations
import org.springframework.security.oauth2.core.AuthenticationMethod
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.converter.ClaimConversionService
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames
import org.springframework.security.oauth2.jwt.MappedJwtClaimSetConverter
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.web.server.ResponseStatusException
import reactor.core.publisher.Mono

/**
 * Constants for OAuth type authentication which are not directly available in the Spring Security.
 */
object OAuthConstants {
    /**
     * Base URL path with placeholders (`{baseUrl}`, `{action}`) for the OAuth redirect URL (`redirect_uri`).
     *
     * @see org.springframework.security.config.oauth2.client.CommonOAuth2Provider
     * @see ClientRegistration
     */
    const val REDIRECT_URL_BASE = "{baseUrl}/{action}/oauth2/code/"
    const val GD_USER_GROUPS_SCOPE = "gd_user_groups"
}

/**
 * Builds [ClientRegistration] from [Organization] retrieved from [AuthenticationStoreClient].
 *
 * @param registrationId registration ID to be used
 * @param organization organization object retrieved from [AuthenticationStoreClient]
 * @param properties static properties for being able to configure pre-configured DEX issuer
 * @param clientRegistrationBuilderCache the cache where non-DEX client registration builders are saved
 * for improving performance
 */
@SuppressWarnings("TooGenericExceptionCaught")
fun buildClientRegistration(
    registrationId: String,
    organization: Organization,
    properties: HostBasedClientRegistrationRepositoryProperties,
    clientRegistrationBuilderCache: ClientRegistrationBuilderCache,
): ClientRegistration =
    if (organization.oauthIssuerLocation != null) {
        clientRegistrationBuilderCache.get(organization.oauthIssuerLocation) {
            try {
                ClientRegistrations.fromIssuerLocation(organization.oauthIssuerLocation)
            } catch (ex: RuntimeException) {
                when (ex) {
                    is IllegalArgumentException,
                    is IllegalStateException,
                    -> throw ResponseStatusException(
                        HttpStatus.UNAUTHORIZED,
                        "Authorization failed for given issuer \"${organization.oauthIssuerLocation}\". ${ex.message}"
                    )

                    else -> throw ex
                }
            }
        }
            .registrationId(registrationId)
            .withRedirectUri(organization.oauthIssuerId)
    } else {
        ClientRegistration
            .withRegistrationId(registrationId)
            .withDexConfig(properties)
    }.buildWithIssuerConfig(organization)

/**
 * Prepares [NimbusReactiveJwtDecoder] that decodes incoming JWTs and validates these against JWKs from [jwkSet] and
 * JWS algorithms specified by [jwsAlgs]
 *
 * @param jwkSet Source of the JWKSet (set of JWK keys against which JWTs should be validated during the authentication)
 * @param jwsAlgs The allowed JWS algorithms for the objects to be verified.
 */
fun prepareJwtDecoder(jwkSet: Mono<JWKSet>, jwsAlgs: Set<JWSAlgorithm>): NimbusReactiveJwtDecoder =
    NimbusReactiveJwtDecoder { signedJwt ->
        jwkSet.map { jwkSet ->
            val jwtProcessor = DefaultJWTProcessor<JWKSecurityContext>()
            val securityContext = JWKSecurityContext(jwkSet.keys)
            jwtProcessor.jwsKeySelector = JWSVerificationKeySelector(
                jwsAlgs,
                JWKSecurityContextJWKSet()
            )
            jwtProcessor.jwtClaimsSetVerifier = ExpTimeCheckingJwtClaimsSetVerifier
            jwtProcessor.process(signedJwt, securityContext)
        }
    }.apply {
        setClaimSetConverter(
            MappedJwtClaimSetConverter.withDefaults(
                mapOf(JWTClaimNames.ISSUED_AT to JwtIssuedAtConverter())
            )
        )
    }

class JwtIssuedAtConverter : Converter<Any, Instant> {

    private val conversionService: ConversionService = ClaimConversionService.getSharedInstance()
    private val objectTypeDescriptor: TypeDescriptor = TypeDescriptor.valueOf(Any::class.java)
    private val instantTypeDescriptor: TypeDescriptor = TypeDescriptor.valueOf(Instant::class.java)

    override fun convert(source: Any): Instant = convertInstant(source)

    private fun convertInstant(source: Any?): Instant {
        if (source == null) {
            throw JwtVerificationException()
        }
        return conversionService.convert(source, objectTypeDescriptor, instantTypeDescriptor) as Instant?
            ?: throw JwtVerificationException()
    }
}

/**
 * Extension of the original [JWTClaimsSetVerifier] used in the [DefaultJWTProcessor] which translates
 * the expired JWT to a special [JwtExpiredException]. The original verifier fails with too generic
 * [BadJWTException] with just "Expired JWT" message which is unprocessable. On the other hand, this extension
 * allows us to handle expired JWTs in easier way.
 */
internal object ExpTimeCheckingJwtClaimsSetVerifier : JWTClaimsSetVerifier<JWKSecurityContext> {
    private const val MAX_CLOCK_SKEW = DefaultJWTClaimsVerifier.DEFAULT_MAX_CLOCK_SKEW_SECONDS.toLong()
    private val defaultVerifier = DefaultJWTClaimsVerifier<SecurityContext>(null, null)
    override fun verify(claimsSet: JWTClaimsSet?, context: JWKSecurityContext) {
        claimsSet?.expirationTime?.let { expTime ->
            val expTimeWithClockSkew = expTime.toInstant().plusSeconds(MAX_CLOCK_SKEW)
            if (Instant.now().isAfter(expTimeWithClockSkew)) {
                throw InternalJwtExpiredException()
            }
        }
        defaultVerifier.verify(claimsSet, context)
    }
}

/**
 * Returns Md5 hash of the input
 * @param input
 * @return md5 hash of the input
 */
fun hashStringWithMD5(input: String): String {
    val md5Digest = MessageDigest.getInstance("MD5")
    val hashBytes = md5Digest.digest(input.toByteArray())

    // Convert the byte array to a hexadecimal string representation
    val hexString = StringBuilder()
    for (byte in hashBytes) {
        hexString.append(String.format("%02x", byte))
    }
    return hexString.toString()
}

/**
 * Adds the redirect URL to this receiver in the case the [oauthIssuerId] is defined, otherwise the default value
 * for this receiver is used.
 *
 * @receiver the [ClientRegistration] builder
 * @param oauthIssuerId the OAuth Issuer ID, can be `null`
 * @return updated receiver
 */
private fun ClientRegistration.Builder.withRedirectUri(oauthIssuerId: String?) = if (oauthIssuerId != null) {
    redirectUri("${OAuthConstants.REDIRECT_URL_BASE}/$oauthIssuerId")
} else this

/**
 * Adds the OIDC issuer configuration to this receiver.
 *
 * @receiver the [ClientRegistration] builder
 * @param organization the organization containing OIDC issuer configuration
 * @return this builder
 */
private fun ClientRegistration.Builder.buildWithIssuerConfig(
    organization: Organization,
): ClientRegistration {
    if (organization.oauthClientId == null || organization.oauthClientSecret == null) {
        throw ResponseStatusException(
            HttpStatus.UNAUTHORIZED,
            "Authorization failed for given issuer ${organization.oauthIssuerLocation}." +
                " Invalid configuration, missing mandatory attribute client id and/or client secret."
        )
    }
    val withIssuerConfigBuilder = clientId(organization.oauthClientId)
        .clientSecret(organization.oauthClientSecret)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .userNameAttributeName("name")
    val supportedScopes = withIssuerConfigBuilder.build().resolveSupportedScopes()

    return withIssuerConfigBuilder.withScopes(supportedScopes).build()
}

private fun ClientRegistration.resolveSupportedScopes() =
    JSONObject(providerDetails.configurationMetadata)
        .takeIf(JSONObject::isNotEmpty)
        ?.let { confMetadata -> OIDCProviderMetadata.parse(confMetadata).scopes }

private fun ClientRegistration.Builder.withScopes(supportedScopes: Scope?): ClientRegistration.Builder {
    // in the future, we could check mandatory scopes against the supported ones
    val mandatoryScopes =
        listOf(OIDCScopeValue.OPENID, OIDCScopeValue.PROFILE).map(Scope.Value::getValue)
    val optionalScopes = supportedScopes
        ?.filter { scope -> scope in listOf(OIDCScopeValue.EMAIL, OIDCScopeValue.OFFLINE_ACCESS) }
        ?.map(Scope.Value::getValue)
        ?.plus(GD_USER_GROUPS_SCOPE)
        ?: listOf()

    return scope(mandatoryScopes + optionalScopes)
}

/**
 * Adds the DEX issuer static configuration to this receiver.
 *
 * @receiver the [ClientRegistration] builder
 * @param properties static properties for being able to configure pre-configured DEX issuer
 * @return this builder
 */
private fun ClientRegistration.Builder.withDexConfig(
    properties: HostBasedClientRegistrationRepositoryProperties,
) = redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
    .authorizationUri("${properties.remoteAddress}/dex/auth")
    .tokenUri("${properties.localAddress}/dex/token")
    .userInfoUri("${properties.localAddress}/dex/userinfo")
    .userInfoAuthenticationMethod(AuthenticationMethod.HEADER)
    .jwkSetUri("${properties.localAddress}/dex/keys")

/**
 * Remove illegal characters from string according to OAuth2 specification
 */
fun String.removeIllegalCharacters(): String = filter(::isLegalChar)

fun findAuthenticatedUser(
    client: AuthenticationStoreClient,
    organization: Organization,
    authentication: Authentication?,
): Mono<User> =
    when (authentication) {
        is UserContextAuthenticationToken -> Mono.just(authentication.user)
        is JwtAuthenticationToken -> getUserForJwt(client, organization.id, authentication)
        is OAuth2AuthenticationToken -> getUserForOAuth2(client, organization, authentication)
        else -> Mono.empty()
    }

fun getUserForJwt(
    client: AuthenticationStoreClient,
    organizationId: String,
    token: JwtAuthenticationToken,
): Mono<User> =
    mono { client.getUserById(organizationId, token.name) }

fun getUserForOAuth2(
    client: AuthenticationStoreClient,
    organization: Organization,
    token: OAuth2AuthenticationToken,
): Mono<User> =
    mono {
        client.getUserByAuthenticationId(organization.id, token.getClaim(organization))
    }

fun Authentication.getClaim(organization: Organization): String =
    when (this) {
        is UserContextAuthenticationToken -> this.user.id
        is OAuth2AuthenticationToken -> this.getClaim(organization.oauthSubjectIdClaim)
        is JwtAuthenticationToken -> this.name
        else -> ""
    }

fun OAuth2AuthenticationToken.getClaim(claimName: String?): String =
    (principal.attributes[claimName ?: IdTokenClaimNames.SUB] as String?)
        ?: throw InvalidBearerTokenException("Token does not contain $claimName claim.")

fun OAuth2AuthenticationToken.getClaimList(claimName: String?): List<String> =
    (principal.attributes[claimName] as List<String>?) ?: emptyList()

/**
 * Detect if character is legal according to OAuth2 specification
 */
@Suppress("MagicNumber")
private fun isLegalChar(c: Char): Boolean =
    (c.code <= 0x7f) && (c.code in 0x20..0x21 || c.code in 0x23..0x5b || c.code in 0x5d..0x7e)

/**
 * Organization and user unless global logout has been triggered or no user has been retrieved.
 */
data class UserContext(
    /**
     * Organization
     */
    val organization: Organization,
    /**
     * User or `null` if no [User] has been found or global logout has been triggered
     */
    val user: User?,
    /**
     * Flag indicating whether authentication flow should be restarted or not
     */
    val restartAuthentication: Boolean,
)

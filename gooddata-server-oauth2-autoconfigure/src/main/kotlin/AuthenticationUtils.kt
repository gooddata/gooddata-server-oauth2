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
@file:Suppress("TooManyFunctions")
package com.gooddata.oauth2.server

import com.gooddata.oauth2.server.OAuthConstants.GD_USER_GROUPS_SCOPE
import com.gooddata.oauth2.server.oauth2.client.fromOidcConfiguration
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
import com.nimbusds.oauth2.sdk.ParseException
import com.nimbusds.oauth2.sdk.Scope
import com.nimbusds.openid.connect.sdk.OIDCScopeValue
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import java.security.MessageDigest
import java.time.Instant
import net.minidev.json.JSONObject
import org.springframework.core.ParameterizedTypeReference
import org.springframework.core.convert.ConversionService
import org.springframework.core.convert.TypeDescriptor
import org.springframework.core.convert.converter.Converter
import org.springframework.http.HttpStatus
import org.springframework.http.RequestEntity
import org.springframework.http.client.SimpleClientHttpRequestFactory
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
import org.springframework.web.client.RestTemplate
import org.springframework.web.server.ResponseStatusException
import org.springframework.web.util.UriComponentsBuilder
import reactor.core.publisher.Mono
import java.net.URI
import java.util.Collections

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
    const val GD_USER_GROUPS_SCOPE = "urn.gooddata.scope/user_groups"
    const val OIDC_METADATA_PATH = "/.well-known/openid-configuration"
    const val CONNECTION_TIMEOUT = 30_000
    const val READ_TIMEOUT = 30_000
}

private val rest: RestTemplate by lazy {
    val requestFactory = SimpleClientHttpRequestFactory().apply {
        setConnectTimeout(OAuthConstants.CONNECTION_TIMEOUT)
        setReadTimeout(OAuthConstants.READ_TIMEOUT)
    }
    RestTemplate().apply {
        this.requestFactory = requestFactory
    }
}

private val typeReference: ParameterizedTypeReference<Map<String, Any>> = object :
    ParameterizedTypeReference<Map<String, Any>>() {}

/**
 * Builds a client registration based on [Organization] details.
 *
 * In the case that the issuer location is an Azure B2C provider, the metadata is retrieved via a separate handler
 * that performs validation on the endpoints instead of the issuer since Azure B2C openid-configuration does not
 * return a matching issuer value.
 *
 * @param registrationId registration ID to be used
 * @param organization organization object retrieved from [AuthenticationStoreClient]
 * @param properties static properties for being able to configure pre-configured DEX issuer
 * @param clientRegistrationBuilderCache the cache where non-DEX client registration builders are saved for improving
 * performance
 * @return A [ClientRegistration]
 */
@SuppressWarnings("TooGenericExceptionCaught")
fun buildClientRegistration(
    registrationId: String,
    organization: Organization,
    properties: HostBasedClientRegistrationRepositoryProperties,
    clientRegistrationBuilderCache: ClientRegistrationBuilderCache,
): ClientRegistration {
    val issuerLocation = organization.oauthIssuerLocation
        ?: return dexClientRegistration(registrationId, properties, organization)

    return clientRegistrationBuilderCache.get(issuerLocation) {
        try {
            if (issuerLocation.toUri().isAzureB2C()) {
                handleAzureB2CClientRegistration(issuerLocation)
            } else {
                ClientRegistrations.fromIssuerLocation(issuerLocation)
            }
        } catch (ex: RuntimeException) {
            handleRuntimeException(ex, issuerLocation)
        } as ClientRegistration.Builder
    }
        .registrationId(registrationId)
        .withRedirectUri(organization.oauthIssuerId)
        .buildWithIssuerConfig(organization)
}

/**
 * Provides a DEX [ClientRegistration] for the given [registrationId] and [organization].
 *
 * @param registrationId Identifier for the client registration.
 * @param properties Properties for host-based client registration repository.
 * @param organization The organization for which to build the client registration.
 * @return A [ClientRegistration] configured with a default Dex configuration.
 */
private fun dexClientRegistration(
    registrationId: String,
    properties: HostBasedClientRegistrationRepositoryProperties,
    organization: Organization
): ClientRegistration = ClientRegistration
    .withRegistrationId(registrationId)
    .withDexConfig(properties)
    .buildWithIssuerConfig(organization)

/**
 * Handles client registration for Azure B2C by validating issuer metadata and building the registration.
 *
 * @param issuerLocation The issuer location URL as a string.
 * @return A configured [ClientRegistration] instance for Azure B2C.
 * @throws ResponseStatusException if the metadata endpoints do not match the issuer location.
 */
private fun handleAzureB2CClientRegistration(
    issuerLocation: String
): ClientRegistration.Builder {
    val issuerUri = URI.create(issuerLocation)
    val metadataUri = buildMetadataUri(issuerUri)
    val configuration = retrieveOidcConfiguration(metadataUri)

    val validationResult = validateAzureB2CMetadata(configuration, issuerUri)
    return if (validationResult.isValid) {
        fromOidcConfiguration(configuration)
    } else {
        val mismatches = validationResult.mismatchedEndpoints.entries.joinToString(separator = "\n") {
            "${it.key}: ${it.value}"
        }
        val missing = validationResult.missingEndpoints.joinToString("\n")
        val baseMessage = "Authorization failed for the given issuer \"$issuerLocation\"."
        val details = buildString {
            if (mismatches.isNotEmpty()) {
                appendLine("Mismatched endpoints:\n$mismatches")
            }
            if (missing.isNotEmpty()) {
                if (mismatches.isNotEmpty()) appendLine()
                appendLine("Missing endpoints:\n$missing")
            }
        }

        throw ResponseStatusException(
            HttpStatus.UNAUTHORIZED,
            if (details.isNotBlank()) "$baseMessage\n\n$details".trim() else baseMessage
        )
    }
}

/**
 * Builds metadata retrieval URI based on the provided [issuer].
 *
 * @param issuer The issuer location URI.
 * @return The constructed [URI] for metadata retrieval.
 */
internal fun buildMetadataUri(issuer: URI): URI {
    return UriComponentsBuilder.fromUri(issuer)
        .replacePath(issuer.path + OAuthConstants.OIDC_METADATA_PATH)
        .build(Collections.emptyMap<String, String>())
}

/**
 * Retrieves the OpenID Connect configuration from the specified metadata [uri].
 *
 * @param uri The URI from which to retrieve the configuration metadata
 * @return The OIDC configuration as a [Map] of [String] to [Any].
 * @throws ResponseStatusException if the configuration metadata cannot be retrieved.
 */
internal fun retrieveOidcConfiguration(uri: URI): Map<String, Any> {
    val request: RequestEntity<Void> = RequestEntity.get(uri).build()
    return rest.exchange(request, typeReference).body
        ?: throw ResponseStatusException(
            HttpStatus.UNAUTHORIZED,
            "Authorization failed: unable to retrieve configuration metadata from \"$uri\"."
        )
}

/**
 * Result of validating endpoint URLs in the metadata against the configured issuer location.
 *
 * @param isValid `true` if all endpoint URLs in the metadata match the configured issuer location; `false` otherwise.
 * @param mismatchedEndpoints A map of endpoint names to their actual URLs for endpoints that do not match the
 * configured issuer location.
 * @param missingEndpoints A set of endpoint names that are missing from the metadata.
 */
data class MetadataValidationResult(
    val isValid: Boolean,
    val mismatchedEndpoints: Map<String, String>,
    val missingEndpoints: Set<String>
)

/**
 * As the issuer in metadata returned from Azure B2C provider is not the same as the configured issuer location,
 * we must instead validate that the endpoint URLs in the metadata start with the configured issuer location.
 *
 * @param configuration The OIDC configuration metadata.
 * @param uri The issuer location URI to validate against.
 * @return A MetadataValidationResult containing whether all endpoint URLs match the configured issuer location,
 *         and a map of any mismatched endpoints with their actual values.
 */
internal fun validateAzureB2CMetadata(
    configuration: Map<String, Any>,
    uri: URI
): MetadataValidationResult {
    val metadata = parse(configuration, OIDCProviderMetadata::parse)
    val unversionedIssuer = uri.toASCIIString().removeVersionSegment()

    val endpoints = mapOf(
        "authorizationEndpointURI" to metadata.authorizationEndpointURI,
        "tokenEndpointURI" to metadata.tokenEndpointURI,
        "endSessionEndpointURI" to metadata.endSessionEndpointURI,
        "jwkSetURI" to metadata.jwkSetURI,
        "userInfoEndpointURI" to metadata.userInfoEndpointURI
    )

    val mismatchedEndpoints = mutableMapOf<String, String>()
    val missingEndpoints = mutableSetOf<String>()

    endpoints.forEach { (key, uri) ->
        if (uri == null) {
            missingEndpoints.add(key)
        } else if (!uri.toASCIIString().startsWith(prefix = unversionedIssuer, ignoreCase = true)) {
            mismatchedEndpoints[key] = uri.toASCIIString()
        }
    }

    return MetadataValidationResult(
        isValid = mismatchedEndpoints.isEmpty() && missingEndpoints.isEmpty(),
        mismatchedEndpoints = mismatchedEndpoints,
        missingEndpoints = missingEndpoints
    )
}

/**
 * Remove version segment from the issuer location URL
 */
internal fun String.removeVersionSegment(): String {
    val regex = Regex("""/v\d+(\.\d+)*""")
    return this.replace(regex, "")
}

/**
 * Handles [RuntimeException]s that may occur during client registration building
 *
 * @param ex The exception that was thrown.
 * @param issuerLocation The issuer location URL as a string, used for error messaging.
 * @throws ResponseStatusException with `UNAUTHORIZED` status for known exception types.
 * @throws RuntimeException for any other exceptions.
 */
private fun handleRuntimeException(ex: RuntimeException, issuerLocation: String) {
    when (ex) {
        is IllegalArgumentException,
        is IllegalStateException -> throw ResponseStatusException(
            HttpStatus.UNAUTHORIZED,
            "Authorization failed for given issuer \"$issuerLocation\". ${ex.message}"
        )
        else -> throw ex
    }
}

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
} else {
    this
}

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
    return withIssuerConfigBuilder.withScopes(supportedScopes, organization.jitEnabled).build()
}

private fun ClientRegistration.resolveSupportedScopes() =
    JSONObject(providerDetails.configurationMetadata)
        .takeIf(JSONObject::isNotEmpty)
        ?.let { confMetadata -> OIDCProviderMetadata.parse(confMetadata).scopes }

private fun ClientRegistration.Builder.withScopes(
    supportedScopes: Scope?,
    jitEnabled: Boolean?
): ClientRegistration.Builder {
    // in the future, we could check mandatory scopes against the supported ones
    val mandatoryScopes = listOf(OIDCScopeValue.OPENID, OIDCScopeValue.PROFILE).map(Scope.Value::getValue)
    val userGroupsScope = if (jitEnabled == true) listOf(OIDCScopeValue.EMAIL.value, GD_USER_GROUPS_SCOPE) else listOf()
    val optionalScopes = supportedScopes
        ?.filter { scope -> scope in listOf(OIDCScopeValue.OFFLINE_ACCESS) }
        ?.map(Scope.Value::getValue)
        ?: listOf()
    return scope(mandatoryScopes + optionalScopes + userGroupsScope)
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

@Suppress("TooGenericExceptionThrown")
fun <T> parse(body: Map<String, Any>, parser: (JSONObject) -> T): T {
    return try {
        parser(JSONObject(body))
    } catch (ex: ParseException) {
        throw RuntimeException(ex)
    }
}

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
        is JwtAuthenticationToken -> client.getUserById(organization.id, authentication.name)
        is OAuth2AuthenticationToken -> client.getUserByAuthenticationId(
            organization.id,
            authentication.getClaim(organization)
        )

        else -> Mono.empty()
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

/**
 * Get claim list from OAuth2 token
 * If the claim is of a type string, split to list based on ',' delimiter.
 * If the claim is of a type list<String>, return as is.
 *
 * @param claimName name of the claim
 * @return content of a given claim as a list of strings or `null` if unable to retrieve
 */
fun OAuth2AuthenticationToken.getClaimList(claimName: String?): List<String>? =
    when (val claim = principal.attributes[claimName]) {
        is String -> claim.split(',')
        is List<*> -> claim.filterIsInstance<String>()
        else -> null
    }

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

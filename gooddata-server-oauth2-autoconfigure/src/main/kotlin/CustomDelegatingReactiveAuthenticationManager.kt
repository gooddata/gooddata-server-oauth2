package com.gooddata.oauth2.server

import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.core.Authentication
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono

class CustomDelegatingReactiveAuthenticationManager(
    vararg delegates: ReactiveAuthenticationManager,
) : ReactiveAuthenticationManager {
    private val logger = KotlinLogging.logger { }
    private val delegates = delegates.toList()

    override fun authenticate(authentication: Authentication): Mono<Authentication> {
        return getOrganizationFromContext().flatMap { organization ->
            logger.logInfo {
                withMessage { "User attempts to authenticate" }
                withAction("login")
                withState("started")
                withOrganizationId(organization.id)
            }
            Flux.fromIterable(delegates)
                .concatMap { delegate ->
                    delegate.authenticate(authentication)
                }
                .doOnError { t ->
                    logger.logError(t) {
                        withAction("login")
                        withState("error")
                        withOrganizationId(organization.id)
                    }
                }.next()
        }
    }
}

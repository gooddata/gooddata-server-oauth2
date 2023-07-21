package com.gooddata.oauth2.server

import mu.KotlinLogging
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
        logger.logInfo {
            withMessage { "User attempts to authenticate" }
            withAction("login")
            withState("started")
        }
        return withOrganizationFromContext().flatMap { organization ->
            val orgId = organization?.id ?: ""
            Flux.fromIterable(delegates)
                .concatMap { delegate ->
                    delegate.authenticate(authentication)
                }
                .doOnError { t ->
                    logger.logError(t) {
                        withAction("login")
                        withState("error")
                    }
                }.next()
                .doOnNext {
                    logger.logInfo {
                        withMessage { "User authenticated" }
                        withAction("login")
                        withState("finished")
                        withOrganizationId(orgId)
                    }
                }
        }
    }
}

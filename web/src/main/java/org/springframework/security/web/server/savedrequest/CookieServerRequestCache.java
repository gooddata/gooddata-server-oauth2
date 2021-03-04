/*
 * Copyright 2002-2020 the original author or authors.
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
 *
 * Forked from https://github.com/spring-projects/spring-security/blob/5.4.0/web/src/main/java/org/springframework/security/web/server/savedrequest/CookieServerRequestCache.java
 */

package org.springframework.security.web.server.savedrequest;

import java.net.URI;
import java.time.Duration;
import java.util.Base64;
import java.util.Collections;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import reactor.core.publisher.Mono;

import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.web.server.util.matcher.AndServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.MediaTypeServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.NegatedServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;

/**
 * An implementation of {@link ServerRequestCache} that saves the requested URI in a
 * cookie.
 *
 * @author Eleftheria Stein
 * @author Mathieu Ouellet
 * @since 5.4
 */
public class CookieServerRequestCache implements ServerRequestCache {

	private static final String REDIRECT_URI_COOKIE_NAME = "REDIRECT_URI";

	private static final Duration COOKIE_MAX_AGE = Duration.ofSeconds(-1);

	private static final Log logger = LogFactory.getLog(CookieServerRequestCache.class);

	private ServerWebExchangeMatcher saveRequestMatcher = createDefaultRequestMatcher();

	/**
	 * Sets the matcher to determine if the request should be saved. The default is to
	 * match on any GET request.
	 * @param saveRequestMatcher the {@link ServerWebExchangeMatcher} that determines if
	 * the request should be saved
	 */
	public void setSaveRequestMatcher(ServerWebExchangeMatcher saveRequestMatcher) {
		Assert.notNull(saveRequestMatcher, "saveRequestMatcher cannot be null");
		this.saveRequestMatcher = saveRequestMatcher;
	}

	@Override
	public Mono<Void> saveRequest(ServerWebExchange exchange) {
		return this.saveRequestMatcher.matches(exchange).filter((m) -> m.isMatch()).map((m) -> exchange.getResponse())
				.map(ServerHttpResponse::getCookies).doOnNext((cookies) -> {
					ResponseCookie redirectUriCookie = createRedirectUriCookie(exchange.getRequest());
					cookies.add(REDIRECT_URI_COOKIE_NAME, redirectUriCookie);
					logger.debug(LogMessage.format("Request added to Cookie: %s", redirectUriCookie));
				}).then();
	}

	@Override
	public Mono<URI> getRedirectUri(ServerWebExchange exchange) {
		MultiValueMap<String, HttpCookie> cookieMap = exchange.getRequest().getCookies();
		return Mono.justOrEmpty(cookieMap.getFirst(REDIRECT_URI_COOKIE_NAME)).map(HttpCookie::getValue)
				.map(CookieServerRequestCache::decodeCookie)
				.onErrorResume(IllegalArgumentException.class, (ex) -> Mono.empty()).map(URI::create);
	}

	@Override
	public Mono<ServerHttpRequest> removeMatchingRequest(ServerWebExchange exchange) {
		return Mono.just(exchange.getResponse()).map(ServerHttpResponse::getCookies).doOnNext(
				(cookies) -> cookies.add(REDIRECT_URI_COOKIE_NAME, invalidateRedirectUriCookie(exchange.getRequest())))
				.thenReturn(exchange.getRequest());
	}

	private static ResponseCookie createRedirectUriCookie(ServerHttpRequest request) {
		String path = request.getPath().pathWithinApplication().value();
		String query = request.getURI().getRawQuery();
		String redirectUri = path + ((query != null) ? "?" + query : "");
		return createResponseCookie(request, encodeCookie(redirectUri), COOKIE_MAX_AGE);
	}

	private static ResponseCookie invalidateRedirectUriCookie(ServerHttpRequest request) {
		return createResponseCookie(request, null, Duration.ZERO);
	}

	private static ResponseCookie createResponseCookie(ServerHttpRequest request, String cookieValue, Duration age) {
		return ResponseCookie.from(REDIRECT_URI_COOKIE_NAME, cookieValue)
				.path(request.getPath().contextPath().value() + "/").maxAge(age).httpOnly(true)
				.secure("https".equalsIgnoreCase(request.getURI().getScheme())).sameSite("Lax").build();
	}

	private static String encodeCookie(String cookieValue) {
		return new String(Base64.getEncoder().encode(cookieValue.getBytes()));
	}

	private static String decodeCookie(String encodedCookieValue) {
		return new String(Base64.getDecoder().decode(encodedCookieValue.getBytes()));
	}

	private static ServerWebExchangeMatcher createDefaultRequestMatcher() {
		ServerWebExchangeMatcher get = ServerWebExchangeMatchers.pathMatchers(HttpMethod.GET, "/**");
		ServerWebExchangeMatcher notFavicon = new NegatedServerWebExchangeMatcher(
				ServerWebExchangeMatchers.pathMatchers("/favicon.*"));
		MediaTypeServerWebExchangeMatcher html = new MediaTypeServerWebExchangeMatcher(MediaType.TEXT_HTML);
		html.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
		return new AndServerWebExchangeMatcher(get, notFavicon, html);
	}

}

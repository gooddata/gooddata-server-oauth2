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
package com.gooddata.oauth2.server.reactive

import kotlinx.coroutines.reactive.awaitFirstOrNull
import reactor.core.publisher.Mono

/**
 * Awaits for the single value [T] from the [Mono] or null value if none is emitted without blocking a thread
 * and returns the resulting value or throws the corresponding exception if this publisher had produced error.
 * This suspending function is cancellable. If the Job of the current coroutine is cancelled or completed
 * while this suspending function is waiting, this function immediately resumes with CancellationException.
 *
 * @see [kotlinx.coroutines.reactive.awaitSingle]
 */
suspend fun <T> Mono<T>.awaitOrNull(): T? = awaitFirstOrNull()

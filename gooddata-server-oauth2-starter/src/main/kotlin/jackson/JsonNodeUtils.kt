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
 * Forked from https://github.com/spring-projects/spring-security/blob/5.4.0/oauth2/oauth2-client/src/main/java/org/springframework/security/oauth2/client/jackson2/JsonNodeUtils.java
 */
package com.gooddata.oauth2.server.jackson

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper

/**
 * Utility class for `JsonNode`.
 *
 * @author Joe Grandja
 * @since 5.3
 */
internal object JsonNodeUtils {
    val STRING_SET: TypeReference<Set<String>> = object : TypeReference<Set<String>>() {}
    val STRING_OBJECT_MAP: TypeReference<Map<String, Any>> = object : TypeReference<Map<String, Any>>() {}
    fun findStringValue(jsonNode: JsonNode?, fieldName: String?): String? {
        if (jsonNode == null) {
            return null
        }
        val value: JsonNode = jsonNode.findValue(fieldName)
        return if (value.isTextual()) value.asText() else null
    }

    fun <T> findValue(
        jsonNode: JsonNode?,
        fieldName: String?,
        valueTypeReference: TypeReference<T>?,
        mapper: ObjectMapper
    ): T? {
        if (jsonNode == null) {
            return null
        }
        val value: JsonNode = jsonNode.findValue(fieldName)
        return if (value.isContainerNode()) mapper.convertValue(value, valueTypeReference) else null
    }

    fun findObjectNode(jsonNode: JsonNode?, fieldName: String?): JsonNode? {
        if (jsonNode == null) {
            return null
        }
        val value: JsonNode = jsonNode.findValue(fieldName)
        return if (value.isObject()) value else null
    }
}

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
package com.gooddata.oauth2.server.common

import com.google.crypto.tink.Aead
import com.google.crypto.tink.CleartextKeysetHandle
import com.google.crypto.tink.JsonKeysetReader
import com.google.crypto.tink.aead.AeadConfig
import org.intellij.lang.annotations.Language
import java.io.File
import java.lang.IllegalArgumentException
import java.security.GeneralSecurityException
import java.util.Base64

/**
 * Class for converting internal string serialization of cookie to external string serialization and back.
 * It currently does two things:
 * * encrypt value with Authenticated Encryption to improve security
 * * encodes with base64, so it is safe to store value in header
 */
class CookieSerializer(
    private val cookieServiceProperties: CookieServiceProperties
) {
    private lateinit var aead: Aead
    @Language("JSON")
    private val defaultKeyset = """
        {
            "primaryKeyId": 482808123,
            "key": [
                {
                    "keyData": {
                        "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
                        "keyMaterialType": "SYMMETRIC",
                        "value": "GiBpR+IuA4xWtq5ZijTXae/Y9plMy0TMMc97wqdOrK7ndA=="
                    },
                    "outputPrefixType": "TINK",
                    "keyId": 482808123,
                    "status": "ENABLED"
                }
            ]
        }
    """

    init {
        AeadConfig.register()
        synchronizeKeyset()
    }

    /**
     * Synchronize in-memory keyset with keyset storage.
     * Currently used only during instance creation.
     * In future it could be called from some timer or file monitor.
     */
    private fun synchronizeKeyset() {
        // TODO - probably mount k8s as file and read it from file
        val keysetReader = if (cookieServiceProperties.keysetFile.isEmpty()) {
            JsonKeysetReader.withBytes(defaultKeyset.toByteArray())
        } else {
            JsonKeysetReader.withFile(File(cookieServiceProperties.keysetFile))
        }
        val keysetHandle = CleartextKeysetHandle.read(keysetReader)
        aead = keysetHandle.getPrimitive(Aead::class.java)
    }

    /**
     * Convert cookie from internal string serialization to external string serialization.
     */
    fun encodeCookie(internalCookie: String): String {
        val encryptedCookie = aead.encrypt(internalCookie.toByteArray(), null)
        return String(Base64.getEncoder().encode(encryptedCookie))
    }

    /**
     * Convert cookie from external string serialization to internal string serialization.
     * If cookie is malformed or can not be authenticated, than it throws 'IllegalArgumentException'.
     *
     * @throws IllegalArgumentException when decryption fails
     */
    fun decodeCookie(externalCookie: String): String {
        val encryptedCookie = Base64.getDecoder().decode(externalCookie.toByteArray())
        val internalCookie = try {
            aead.decrypt(encryptedCookie, null)
        } catch (_: GeneralSecurityException) {
            throw IllegalArgumentException("Decrypt failed")
        }
        return String(internalCookie)
    }
}

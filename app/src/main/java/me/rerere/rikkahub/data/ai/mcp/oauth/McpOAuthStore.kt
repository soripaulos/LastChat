package me.rerere.rikkahub.data.ai.mcp.oauth

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * AES/GCM-encrypted, on-disk store for MCP OAuth credentials, keyed by server id. Modeled on
 * [me.rerere.rikkahub.data.codex.CodexCredentialStore]: the key lives in the AndroidKeyStore
 * and never leaves it, the payload is written atomically via a temp file, and any
 * decryption/parse failure degrades to an empty state rather than crashing.
 *
 * Access tokens and refresh tokens are secrets, so they deliberately do NOT live in the plain
 * Settings datastore alongside the rest of the MCP config.
 */
class McpOAuthStore(
    context: Context,
    private val json: Json,
) {
    private val file = File(context.noBackupFilesDir, FILE_NAME)

    @Synchronized
    fun read(): McpOAuthState {
        if (!file.exists()) return McpOAuthState()
        return runCatching {
            val bytes = file.readBytes()
            require(bytes.size > IV_SIZE)
            val iv = bytes.copyOfRange(0, IV_SIZE)
            val encrypted = bytes.copyOfRange(IV_SIZE, bytes.size)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(TAG_LENGTH, iv))
            json.decodeFromString<McpOAuthState>(cipher.doFinal(encrypted).decodeToString())
        }.getOrElse {
            McpOAuthState()
        }
    }

    @Synchronized
    fun write(state: McpOAuthState) {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val encrypted = cipher.doFinal(json.encodeToString(state).encodeToByteArray())
        val temporary = File(file.parentFile, "$FILE_NAME.tmp")
        temporary.writeBytes(cipher.iv + encrypted)
        temporary.copyTo(file, overwrite = true)
        temporary.delete()
    }

    @Synchronized
    fun get(serverId: String): McpOAuthRecord? =
        read().records.firstOrNull { it.serverId == serverId }

    @Synchronized
    fun put(record: McpOAuthRecord) {
        val state = read()
        write(
            state.copy(
                records = state.records.filterNot { it.serverId == record.serverId } + record
            )
        )
    }

    @Synchronized
    fun remove(serverId: String) {
        val state = read()
        write(state.copy(records = state.records.filterNot { it.serverId == serverId }))
    }

    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE).run {
            init(
                KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build()
            )
            generateKey()
        }
    }

    private companion object {
        const val FILE_NAME = "mcp_oauth.enc"
        const val KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "rikkahub_mcp_oauth"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val IV_SIZE = 12
        const val TAG_LENGTH = 128
    }
}

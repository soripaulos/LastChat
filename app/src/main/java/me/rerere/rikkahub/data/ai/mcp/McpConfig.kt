package me.rerere.rikkahub.data.ai.mcp

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import me.rerere.ai.core.InputSchema
import kotlin.uuid.Uuid

@Serializable
data class McpCommonOptions(
    val enable: Boolean = true,
    val name: String = "",
    val headers: List<Pair<String, String>> = emptyList(),
    val tools: List<McpTool> = emptyList(),
    // When non-null and enabled, the server is reached using an OAuth 2.1 access token
    // (Authorization: Bearer ...) obtained via the MCP authorization flow instead of a
    // statically configured header. Tokens themselves are never stored here — only the
    // opt-in flag and optional hints live in Settings; secrets live in the encrypted
    // McpOAuthStore keyed by the server id. Defaulting to null keeps existing stored
    // configs (and the JSON import format) backward-compatible.
    val oauth: McpOAuthConfig? = null,
)

/**
 * Per-server OAuth opt-in. Only non-secret hints live here; the access/refresh tokens and
 * the dynamically-registered client credentials are persisted separately in the encrypted
 * [me.rerere.rikkahub.data.ai.mcp.oauth.McpOAuthStore].
 *
 * @param enabled whether to authenticate this server with OAuth.
 * @param scope optional space-delimited scope override. When blank, the scopes advertised by
 *   the server's discovery metadata are used (falling back to a sensible default).
 */
@Serializable
data class McpOAuthConfig(
    val enabled: Boolean = false,
    val scope: String = "",
)

@Serializable
data class McpTool(
    val enable: Boolean = true,
    val name: String = "",
    val description: String? = null,
    val inputSchema: InputSchema? = null
)

@Serializable
sealed class McpServerConfig {
    abstract val id: Uuid
    abstract val commonOptions: McpCommonOptions

    abstract fun clone(
        id: Uuid = this.id,
        commonOptions: McpCommonOptions = this.commonOptions
    ): McpServerConfig

    @Serializable
    @SerialName("sse")
    data class SseTransportServer(
        override val id: Uuid = Uuid.random(),
        override val commonOptions: McpCommonOptions = McpCommonOptions(),
        val url: String = "",
    ) : McpServerConfig() {
        override fun clone(id: Uuid, commonOptions: McpCommonOptions): McpServerConfig {
            return copy(id = id, commonOptions = commonOptions)
        }
    }

    @Serializable
    @SerialName("streamable_http")
    data class StreamableHTTPServer(
        override val id: Uuid = Uuid.random(),
        override val commonOptions: McpCommonOptions,
        val url: String = "",
    ) : McpServerConfig() {
        override fun clone(id: Uuid, commonOptions: McpCommonOptions): McpServerConfig {
            return copy(id = id, commonOptions = commonOptions)
        }
    }
}

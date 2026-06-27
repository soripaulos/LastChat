package me.rerere.rikkahub.data.ai.mcp.oauth

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Everything we need to keep talking to one OAuth-protected MCP server, persisted (encrypted)
 * across app restarts. One record per MCP server id.
 *
 * The endpoints are cached from the discovery step so a token refresh after restart doesn't
 * need to re-run discovery. The dynamically-registered [clientId]/[clientSecret] are reused as
 * long as [redirectUri] still matches the callback the app can bind; otherwise the manager
 * re-registers.
 */
@Serializable
data class McpOAuthRecord(
    val serverId: String,
    // Canonical resource identifier of the MCP server (RFC 8707 `resource` parameter).
    val resource: String = "",
    val authorizationEndpoint: String = "",
    val tokenEndpoint: String = "",
    val registrationEndpoint: String = "",
    val scope: String = "",
    val clientId: String = "",
    val clientSecret: String? = null,
    val redirectUri: String = "",
    val accessToken: String = "",
    val refreshToken: String? = null,
    val tokenType: String = "Bearer",
    // Epoch millis when [accessToken] expires; 0 means "unknown / never fetched".
    val expiresAt: Long = 0L,
) {
    val hasTokens: Boolean get() = accessToken.isNotBlank()
}

@Serializable
data class McpOAuthState(
    val records: List<McpOAuthRecord> = emptyList(),
)

/**
 * OAuth 2.0 Authorization Server Metadata (RFC 8414) / OpenID Connect discovery document.
 * Only the fields we consume are modeled; unknown keys are ignored by the parser.
 */
@Serializable
data class AuthServerMetadata(
    @SerialName("issuer") val issuer: String? = null,
    @SerialName("authorization_endpoint") val authorizationEndpoint: String? = null,
    @SerialName("token_endpoint") val tokenEndpoint: String? = null,
    @SerialName("registration_endpoint") val registrationEndpoint: String? = null,
    @SerialName("scopes_supported") val scopesSupported: List<String>? = null,
    @SerialName("code_challenge_methods_supported") val codeChallengeMethodsSupported: List<String>? = null,
)

/**
 * OAuth 2.0 Protected Resource Metadata (RFC 9728). Points at the authorization server(s)
 * that can issue tokens for this MCP server.
 */
@Serializable
data class ProtectedResourceMetadata(
    @SerialName("resource") val resource: String? = null,
    @SerialName("authorization_servers") val authorizationServers: List<String>? = null,
    @SerialName("scopes_supported") val scopesSupported: List<String>? = null,
)

/**
 * Dynamic Client Registration response (RFC 7591). Only the fields we use are modeled.
 */
@Serializable
data class ClientRegistrationResponse(
    @SerialName("client_id") val clientId: String? = null,
    @SerialName("client_secret") val clientSecret: String? = null,
)

/**
 * UI-facing state of an OAuth interaction for a given server.
 */
sealed interface McpOAuthStatus {
    data object Idle : McpOAuthStatus

    /** Discovery / registration / browser hand-off in progress, or the token exchange is running. */
    data object Authorizing : McpOAuthStatus

    /** A valid access token is held for this server. */
    data object Authorized : McpOAuthStatus

    data class Error(val message: String) : McpOAuthStatus
}

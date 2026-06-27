package me.rerere.rikkahub.data.ai.mcp.oauth

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.Uri
import android.os.Build
import android.util.Log
import io.ktor.http.ContentType
import io.ktor.server.application.call
import io.ktor.server.cio.CIO
import io.ktor.server.cio.CIOApplicationEngine
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.embeddedServer
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.encodeToString
import me.rerere.common.http.await
import me.rerere.rikkahub.R
import me.rerere.rikkahub.data.ai.mcp.McpServerConfig
import okhttp3.FormBody
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.net.URLEncoder
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import kotlin.coroutines.resume

/**
 * Implements the MCP authorization flow (OAuth 2.1 with PKCE + Dynamic Client Registration)
 * so a user can connect an OAuth-protected MCP server — e.g. Frappe Assistant Core — by only
 * entering the server URL. The flow mirrors what ChatGPT / Claude desktop connectors do:
 *
 *  1. Discover the protected-resource metadata (RFC 9728) and the authorization-server
 *     metadata (RFC 8414 / OpenID Connect discovery) starting from the server URL.
 *  2. Dynamically register this app as an OAuth client (RFC 7591), reusing a previously
 *     registered client when the callback redirect URI still matches.
 *  3. Open the system browser to the authorization endpoint with a PKCE challenge. The user
 *     signs in to their Frappe/ERPNext site and approves access.
 *  4. The browser is redirected to a loopback callback served in-process; we exchange the
 *     authorization code for tokens and persist them (encrypted, via [McpOAuthStore]).
 *  5. [getValidAccessToken] hands the (auto-refreshed) bearer token to [McpManager] which
 *     injects it as `Authorization: Bearer ...` on every transport request.
 *
 * The loopback-callback + deep-link-bounce mechanism is intentionally identical to
 * [me.rerere.rikkahub.data.codex.CodexOAuthManager] so both flows behave the same way and
 * share the app's existing `rikkahub://` redirect handling.
 */
class McpOAuthManager(
    private val context: Context,
    private val scope: CoroutineScope,
    private val client: OkHttpClient,
    private val json: Json,
    private val store: McpOAuthStore,
) {
    private var server: EmbeddedServer<CIOApplicationEngine, CIOApplicationEngine.Configuration>? = null
    private var callbackPort: Int? = null
    private val sessions = ConcurrentHashMap<String, PendingAuth>()
    private val refreshLocks = ConcurrentHashMap<String, Mutex>()

    // In-memory mirror of "which servers currently hold tokens", seeded once from the encrypted
    // store. This keeps isAuthorized()/status lookups off the disk so they're safe to call from
    // Compose on the main thread; the encrypted store itself is only touched on IO dispatchers.
    private val authorizedIds = ConcurrentHashMap.newKeySet<String>().apply {
        runCatching { store.read().records.filter { it.hasTokens }.forEach { add(it.serverId) } }
    }

    private val _status = MutableStateFlow<Map<String, McpOAuthStatus>>(emptyMap())
    val status: StateFlow<Map<String, McpOAuthStatus>> = _status.asStateFlow()

    /** Observe the OAuth status for a single server, falling back to the persisted state. */
    fun statusFor(serverId: String): Flow<McpOAuthStatus> = status.map { map ->
        map[serverId] ?: defaultStatus(serverId)
    }

    fun currentStatus(serverId: String): McpOAuthStatus =
        _status.value[serverId] ?: defaultStatus(serverId)

    fun isAuthorized(serverId: String): Boolean = authorizedIds.contains(serverId)

    private fun defaultStatus(serverId: String): McpOAuthStatus =
        if (isAuthorized(serverId)) McpOAuthStatus.Authorized else McpOAuthStatus.Idle

    /** Clear the dialog state after the UI has shown a terminal (success/error) result. */
    fun consumeResult(serverId: String) {
        setStatus(serverId, defaultStatus(serverId))
    }

    /**
     * Start (or restart) the authorization flow for [config]. Runs entirely off the main
     * thread; progress is reported through [status]. Safe to call repeatedly — a new attempt
     * supersedes any in-flight one for the same server.
     */
    fun startLogin(config: McpServerConfig) {
        val serverId = config.id.toString()
        val mcpUrl = urlOf(config).trim()
        if (mcpUrl.isBlank()) {
            setStatus(serverId, McpOAuthStatus.Error(context.getString(R.string.mcp_oauth_missing_url)))
            return
        }
        val scopeOverride = config.commonOptions.oauth?.scope?.trim().orEmpty()
        setStatus(serverId, McpOAuthStatus.Authorizing)
        scope.launch {
            var state: String? = null
            try {
                val port = ensureCallbackServer()
                val redirectUri = "http://127.0.0.1:$port$CALLBACK_PATH"

                val discovery = discover(mcpUrl)
                val resolvedScope = resolveScope(scopeOverride, discovery)

                val existing = store.get(serverId)
                val reuseClient = existing != null &&
                    existing.clientId.isNotBlank() &&
                    existing.redirectUri == redirectUri &&
                    existing.registrationEndpoint == discovery.registrationEndpoint
                val clientId: String
                val clientSecret: String?
                if (reuseClient) {
                    clientId = existing!!.clientId
                    clientSecret = existing.clientSecret
                } else {
                    val registration = registerClient(discovery.registrationEndpoint, redirectUri, resolvedScope)
                    clientId = registration.first
                    clientSecret = registration.second
                }

                val verifier = randomUrlSafe(64)
                val challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(verifier.encodeToByteArray())
                )
                val newState = randomUrlSafe(32)
                state = newState
                sessions[newState] = PendingAuth(
                    serverId = serverId,
                    discovery = discovery,
                    scope = resolvedScope,
                    clientId = clientId,
                    clientSecret = clientSecret,
                    redirectUri = redirectUri,
                    verifier = verifier,
                )

                val authUrl = Uri.parse(discovery.authorizationEndpoint).buildUpon()
                    .appendQueryParameter("response_type", "code")
                    .appendQueryParameter("client_id", clientId)
                    .appendQueryParameter("redirect_uri", redirectUri)
                    .appendQueryParameter("code_challenge", challenge)
                    .appendQueryParameter("code_challenge_method", "S256")
                    .appendQueryParameter("state", newState)
                    .apply {
                        if (resolvedScope.isNotBlank()) appendQueryParameter("scope", resolvedScope)
                        if (discovery.resource.isNotBlank()) appendQueryParameter("resource", discovery.resource)
                    }
                    .build()

                context.startActivity(
                    Intent(Intent.ACTION_VIEW, authUrl).apply {
                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    }
                )
            } catch (error: Throwable) {
                state?.let(sessions::remove)
                Log.e(TAG, "startLogin failed for $mcpUrl", error)
                setStatus(
                    serverId,
                    McpOAuthStatus.Error(
                        if (error.message == CALLBACK_PORTS_UNAVAILABLE) {
                            context.getString(R.string.mcp_oauth_ports_unavailable)
                        } else {
                            error.message ?: context.getString(R.string.mcp_oauth_failed)
                        }
                    )
                )
            }
        }
    }

    /** Forget all OAuth credentials for a server (used on sign-out and server deletion). */
    fun signOut(serverId: String) {
        store.remove(serverId)
        authorizedIds.remove(serverId)
        setStatus(serverId, McpOAuthStatus.Idle)
    }

    /**
     * Return a non-expired access token for [serverId], refreshing it first if necessary.
     * Returns null when the server isn't authorized or the refresh failed (the caller should
     * surface an "authorization required" state in that case).
     */
    suspend fun getValidAccessToken(serverId: String): String? {
        val record = store.get(serverId) ?: return null
        if (!record.hasTokens) return null
        if (record.expiresAt == 0L || record.expiresAt > System.currentTimeMillis() + REFRESH_MARGIN_MS) {
            return record.accessToken
        }
        return refreshLocks.getOrPut(serverId) { Mutex() }.withLock {
            // Re-read inside the lock: another caller may have refreshed while we waited.
            val current = store.get(serverId) ?: return@withLock null
            if (current.expiresAt == 0L || current.expiresAt > System.currentTimeMillis() + REFRESH_MARGIN_MS) {
                return@withLock current.accessToken
            }
            runCatching { refresh(current) }
                .onFailure { Log.w(TAG, "token refresh failed for $serverId", it) }
                .getOrNull()
                ?.accessToken
        }
    }

    // --- Discovery -----------------------------------------------------------------------

    private suspend fun discover(mcpUrl: String): DiscoveryResult {
        val origin = originOf(mcpUrl)
        val path = runCatching { Uri.parse(mcpUrl).path.orEmpty() }.getOrDefault("")

        val prm = fetchProtectedResourceMetadata(origin, path)
        val resource = prm?.resource?.takeIf { it.isNotBlank() } ?: mcpUrl
        val authServerBase = prm?.authorizationServers?.firstOrNull()?.takeIf { it.isNotBlank() } ?: origin

        val asm = fetchAuthServerMetadata(authServerBase)
            ?: error(context.getString(R.string.mcp_oauth_discovery_failed))

        val authorizationEndpoint = asm.authorizationEndpoint?.takeIf { it.isNotBlank() }
            ?: error(context.getString(R.string.mcp_oauth_discovery_failed))
        val tokenEndpoint = asm.tokenEndpoint?.takeIf { it.isNotBlank() }
            ?: error(context.getString(R.string.mcp_oauth_discovery_failed))
        val registrationEndpoint = asm.registrationEndpoint?.takeIf { it.isNotBlank() }
            ?: error(context.getString(R.string.mcp_oauth_no_registration))

        return DiscoveryResult(
            resource = resource,
            authorizationEndpoint = authorizationEndpoint,
            tokenEndpoint = tokenEndpoint,
            registrationEndpoint = registrationEndpoint,
            scopesSupported = (prm?.scopesSupported ?: asm.scopesSupported).orEmpty(),
        )
    }

    private suspend fun fetchProtectedResourceMetadata(
        origin: String,
        path: String,
    ): ProtectedResourceMetadata? {
        val candidates = buildList {
            if (path.isNotBlank() && path != "/") {
                add(joinUrl(origin, "/.well-known/oauth-protected-resource") + path)
            }
            add(joinUrl(origin, "/.well-known/oauth-protected-resource"))
        }
        for (url in candidates) {
            val parsed = getJson<ProtectedResourceMetadata>(url) ?: continue
            if (!parsed.authorizationServers.isNullOrEmpty() || !parsed.resource.isNullOrBlank()) {
                return parsed
            }
        }
        return null
    }

    private suspend fun fetchAuthServerMetadata(authServerBase: String): AuthServerMetadata? {
        val base = authServerBase.trimEnd('/')
        val origin = originOf(authServerBase)
        val candidates = linkedSetOf(
            "$base/.well-known/oauth-authorization-server",
            "$base/.well-known/openid-configuration",
            joinUrl(origin, "/.well-known/oauth-authorization-server"),
            joinUrl(origin, "/.well-known/openid-configuration"),
        )
        for (url in candidates) {
            val parsed = getJson<AuthServerMetadata>(url) ?: continue
            if (!parsed.authorizationEndpoint.isNullOrBlank() && !parsed.tokenEndpoint.isNullOrBlank()) {
                return parsed
            }
        }
        return null
    }

    // --- Dynamic client registration -----------------------------------------------------

    private suspend fun registerClient(
        registrationEndpoint: String,
        redirectUri: String,
        scope: String,
    ): Pair<String, String?> {
        val payload = buildJsonObject {
            put("client_name", "RikkaHub Agent")
            put("token_endpoint_auth_method", "none")
            put("application_type", "native")
            putJsonArray("redirect_uris") { add(redirectUri) }
            putJsonArray("grant_types") {
                add("authorization_code")
                add("refresh_token")
            }
            putJsonArray("response_types") { add("code") }
            if (scope.isNotBlank()) put("scope", scope)
        }
        val response = withContext(Dispatchers.IO) {
            client.newCall(
                Request.Builder()
                    .url(registrationEndpoint)
                    .addHeader("Accept", "application/json")
                    .post(json.encodeToString(payload).toRequestBody(JSON_MEDIA_TYPE))
                    .build()
            ).await()
        }
        val body = response.body.string()
        if (!response.isSuccessful) {
            error(context.getString(R.string.mcp_oauth_registration_failed, response.code))
        }
        val registration = runCatching {
            json.decodeFromString<ClientRegistrationResponse>(body)
        }.getOrNull()
        val clientId = registration?.clientId?.takeIf { it.isNotBlank() }
            ?: error(context.getString(R.string.mcp_oauth_registration_failed, response.code))
        return clientId to registration?.clientSecret
    }

    // --- Token exchange / refresh --------------------------------------------------------

    private suspend fun exchangeCode(code: String, pending: PendingAuth): McpOAuthRecord {
        val form = FormBody.Builder()
            .add("grant_type", "authorization_code")
            .add("code", code)
            .add("redirect_uri", pending.redirectUri)
            .add("code_verifier", pending.verifier)
            .add("client_id", pending.clientId)
            .apply {
                if (pending.discovery.resource.isNotBlank()) add("resource", pending.discovery.resource)
                pending.clientSecret?.let { add("client_secret", it) }
            }
            .build()
        val response = withContext(Dispatchers.IO) {
            client.newCall(
                Request.Builder()
                    .url(pending.discovery.tokenEndpoint)
                    .addHeader("Accept", "application/json")
                    .post(form)
                    .build()
            ).await()
        }
        val body = response.body.string()
        if (!response.isSuccessful) {
            error(context.getString(R.string.mcp_oauth_token_failed, response.code))
        }
        val token = json.parseToJsonElement(body).jsonObject
        val accessToken = token["access_token"]?.jsonPrimitive?.contentOrNull
            ?: error(context.getString(R.string.mcp_oauth_token_failed, response.code))
        val record = McpOAuthRecord(
            serverId = pending.serverId,
            resource = pending.discovery.resource,
            authorizationEndpoint = pending.discovery.authorizationEndpoint,
            tokenEndpoint = pending.discovery.tokenEndpoint,
            registrationEndpoint = pending.discovery.registrationEndpoint,
            scope = token["scope"]?.jsonPrimitive?.contentOrNull ?: pending.scope,
            clientId = pending.clientId,
            clientSecret = pending.clientSecret,
            redirectUri = pending.redirectUri,
            accessToken = accessToken,
            refreshToken = token["refresh_token"]?.jsonPrimitive?.contentOrNull,
            tokenType = token["token_type"]?.jsonPrimitive?.contentOrNull ?: "Bearer",
            expiresAt = expiresAtFrom(token["expires_in"]?.jsonPrimitive?.contentOrNull),
        )
        store.put(record)
        authorizedIds.add(record.serverId)
        return record
    }

    private suspend fun refresh(record: McpOAuthRecord): McpOAuthRecord? {
        val refreshToken = record.refreshToken?.takeIf { it.isNotBlank() } ?: run {
            // No refresh token: the existing access token is the best we have. If it's already
            // expired there's nothing to do but require a fresh sign-in.
            store.put(record.copy(accessToken = "", refreshToken = null, expiresAt = 0L))
            authorizedIds.remove(record.serverId)
            setStatus(record.serverId, McpOAuthStatus.Error(context.getString(R.string.mcp_oauth_reauth_required)))
            return null
        }
        val form = FormBody.Builder()
            .add("grant_type", "refresh_token")
            .add("refresh_token", refreshToken)
            .add("client_id", record.clientId)
            .apply {
                if (record.scope.isNotBlank()) add("scope", record.scope)
                if (record.resource.isNotBlank()) add("resource", record.resource)
                record.clientSecret?.let { add("client_secret", it) }
            }
            .build()
        val response = withContext(Dispatchers.IO) {
            client.newCall(
                Request.Builder()
                    .url(record.tokenEndpoint)
                    .addHeader("Accept", "application/json")
                    .post(form)
                    .build()
            ).await()
        }
        val body = response.body.string()
        if (!response.isSuccessful) {
            // A rejected refresh token means the user must sign in again; drop the tokens but
            // keep the registered client so re-auth doesn't have to re-register.
            store.put(record.copy(accessToken = "", refreshToken = null, expiresAt = 0L))
            authorizedIds.remove(record.serverId)
            setStatus(record.serverId, McpOAuthStatus.Error(context.getString(R.string.mcp_oauth_reauth_required)))
            return null
        }
        val token = json.parseToJsonElement(body).jsonObject
        val updated = record.copy(
            accessToken = token["access_token"]?.jsonPrimitive?.contentOrNull ?: record.accessToken,
            refreshToken = token["refresh_token"]?.jsonPrimitive?.contentOrNull ?: record.refreshToken,
            tokenType = token["token_type"]?.jsonPrimitive?.contentOrNull ?: record.tokenType,
            expiresAt = expiresAtFrom(token["expires_in"]?.jsonPrimitive?.contentOrNull),
        )
        store.put(updated)
        setStatus(record.serverId, McpOAuthStatus.Authorized)
        return updated
    }

    // --- Loopback callback server --------------------------------------------------------

    @Synchronized
    private fun ensureCallbackServer(): Int {
        callbackPort?.let { return it }
        var lastError: Throwable? = null
        for (port in CALLBACK_PORTS) {
            try {
                server = embeddedServer(CIO, host = "127.0.0.1", port = port) {
                    routing {
                        get(CALLBACK_PATH) {
                            val callbackState = call.request.queryParameters["state"]
                            val code = call.request.queryParameters["code"]
                            val error = call.request.queryParameters["error"]
                            val pending = callbackState?.let(sessions::remove)
                            when {
                                pending == null -> {
                                    call.respondText(callbackPage(false), ContentType.Text.Html)
                                }

                                !error.isNullOrBlank() -> {
                                    setStatus(pending.serverId, McpOAuthStatus.Error(error))
                                    call.respondText(callbackPage(false), ContentType.Text.Html)
                                }

                                code.isNullOrBlank() -> {
                                    setStatus(
                                        pending.serverId,
                                        McpOAuthStatus.Error(context.getString(R.string.mcp_oauth_failed)),
                                    )
                                    call.respondText(callbackPage(false), ContentType.Text.Html)
                                }

                                else -> {
                                    call.respondText(callbackPage(true), ContentType.Text.Html)
                                    scope.launch {
                                        try {
                                            awaitNetworkUnblocked()
                                            exchangeCode(code, pending)
                                            setStatus(pending.serverId, McpOAuthStatus.Authorized)
                                        } catch (error: Throwable) {
                                            Log.e(TAG, "token exchange failed", error)
                                            setStatus(
                                                pending.serverId,
                                                McpOAuthStatus.Error(
                                                    error.message
                                                        ?: context.getString(R.string.mcp_oauth_token_exchange_failed),
                                                ),
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }.start(wait = false)
                callbackPort = port
                return port
            } catch (error: Throwable) {
                lastError = error
            }
        }
        throw IllegalStateException(CALLBACK_PORTS_UNAVAILABLE, lastError)
    }

    private suspend fun awaitNetworkUnblocked() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return
        val connectivityManager = context.getSystemService(ConnectivityManager::class.java) ?: return
        suspendCancellableCoroutine { continuation ->
            lateinit var callback: ConnectivityManager.NetworkCallback
            callback = object : ConnectivityManager.NetworkCallback() {
                override fun onBlockedStatusChanged(network: Network, blocked: Boolean) {
                    if (!blocked && continuation.isActive) {
                        runCatching { connectivityManager.unregisterNetworkCallback(callback) }
                        continuation.resume(Unit)
                    }
                }
            }
            continuation.invokeOnCancellation {
                runCatching { connectivityManager.unregisterNetworkCallback(callback) }
            }
            connectivityManager.registerDefaultNetworkCallback(callback)
        }
    }

    private fun callbackPage(success: Boolean): String {
        val statusParam = if (success) "success" else "error"
        val deepLink = "rikkahub://mcp/oauth?status=" +
            URLEncoder.encode(statusParam, Charsets.UTF_8.name())
        return """
            <!doctype html>
            <html>
              <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <meta http-equiv="refresh" content="0; url=$deepLink">
                <title>RikkaHub MCP OAuth</title>
              </head>
              <body>
                <p>${if (success) "Returning to RikkaHub..." else "Sign-in failed."}</p>
                <p><a href="$deepLink">Return to RikkaHub</a></p>
                <script>
                  window.location.replace("$deepLink");
                  setTimeout(function () { window.location.href = "$deepLink"; }, 500);
                </script>
              </body>
            </html>
        """.trimIndent()
    }

    // --- Helpers -------------------------------------------------------------------------

    private suspend inline fun <reified T> getJson(url: String): T? {
        return runCatching {
            val response = withContext(Dispatchers.IO) {
                client.newCall(
                    Request.Builder()
                        .url(url)
                        .addHeader("Accept", "application/json")
                        .get()
                        .build()
                ).await()
            }
            val body = response.body.string()
            if (!response.isSuccessful || body.isBlank()) return@runCatching null
            json.decodeFromString<T>(body)
        }.getOrNull()
    }

    private fun resolveScope(override: String, discovery: DiscoveryResult): String = when {
        override.isNotBlank() -> override
        discovery.scopesSupported.isNotEmpty() -> discovery.scopesSupported.joinToString(" ")
        else -> DEFAULT_SCOPE
    }

    private fun setStatus(serverId: String, status: McpOAuthStatus) {
        _status.value = _status.value.toMutableMap().apply { put(serverId, status) }
    }

    private fun expiresAtFrom(expiresIn: String?): Long {
        val seconds = expiresIn?.toLongOrNull() ?: return 0L
        return System.currentTimeMillis() + seconds * 1000
    }

    private fun randomUrlSafe(size: Int): String {
        val bytes = ByteArray(size)
        SecureRandom().nextBytes(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    private fun urlOf(config: McpServerConfig): String = when (config) {
        is McpServerConfig.SseTransportServer -> config.url
        is McpServerConfig.StreamableHTTPServer -> config.url
    }

    private fun originOf(url: String): String {
        val uri = Uri.parse(url)
        val scheme = uri.scheme ?: "https"
        val host = uri.host ?: return url.trimEnd('/')
        val port = uri.port
        return buildString {
            append(scheme).append("://").append(host)
            if (port != -1) append(':').append(port)
        }
    }

    private fun joinUrl(base: String, suffix: String): String =
        base.trimEnd('/') + "/" + suffix.trimStart('/')

    companion object {
        private const val TAG = "McpOAuthManager"
        private const val CALLBACK_PORTS_UNAVAILABLE = "MCP OAuth callback ports are unavailable"
        private const val CALLBACK_PATH = "/mcp/oauth/callback"
        private const val DEFAULT_SCOPE = "openid"
        private const val REFRESH_MARGIN_MS = 60_000L

        // Distinct from the Codex callback ports so both flows can coexist. These are the
        // redirect URIs registered via DCR; keeping them stable lets the registered client be
        // reused across logins.
        private val CALLBACK_PORTS = listOf(49215, 49216, 49217)
        private val JSON_MEDIA_TYPE = "application/json; charset=utf-8".toMediaType()
    }
}

private data class PendingAuth(
    val serverId: String,
    val discovery: DiscoveryResult,
    val scope: String,
    val clientId: String,
    val clientSecret: String?,
    val redirectUri: String,
    val verifier: String,
)

internal data class DiscoveryResult(
    val resource: String,
    val authorizationEndpoint: String,
    val tokenEndpoint: String,
    val registrationEndpoint: String,
    val scopesSupported: List<String>,
)

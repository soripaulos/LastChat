package me.rerere.rikkahub.data.ai.mcp

import android.content.Context
import android.util.Log
import io.modelcontextprotocol.kotlin.sdk.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.Implementation
import io.modelcontextprotocol.kotlin.sdk.Tool
import io.modelcontextprotocol.kotlin.sdk.client.Client
import io.modelcontextprotocol.kotlin.sdk.shared.AbstractTransport
import io.modelcontextprotocol.kotlin.sdk.shared.RequestOptions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.ClassDiscriminatorMode
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.encodeToJsonElement
import me.rerere.ai.core.InputSchema
import me.rerere.rikkahub.AppScope
import me.rerere.rikkahub.R
import me.rerere.rikkahub.data.ai.mcp.oauth.McpOAuthManager
import me.rerere.rikkahub.data.ai.mcp.oauth.McpOAuthStatus
import me.rerere.rikkahub.data.datastore.SettingsStore
import me.rerere.rikkahub.data.datastore.getCurrentAssistant
import me.rerere.rikkahub.data.ai.mcp.transport.SseClientTransport
import me.rerere.rikkahub.data.ai.mcp.transport.StreamableHttpClientTransport
import me.rerere.rikkahub.utils.checkDifferent
import okhttp3.OkHttpClient
import java.util.concurrent.TimeUnit
import kotlin.time.Duration.Companion.seconds
import kotlin.uuid.Uuid

private const val TAG = "McpManager"

class McpManager(
    private val context: Context,
    private val settingsStore: SettingsStore,
    private val appScope: AppScope,
    private val oauthManager: McpOAuthManager,
) {
    private val okHttpClient: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(20, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.MINUTES)
        .writeTimeout(120, TimeUnit.SECONDS)
        .followSslRedirects(true)
        .followRedirects(true)
        .build()

    private val clients: MutableMap<McpServerConfig, Client> = mutableMapOf()
    val syncingStatus = MutableStateFlow<Map<Uuid, McpStatus>>(mapOf())

    init {
        appScope.launch {
            settingsStore.settingsFlow
                .map { settings -> settings.mcpServers }
                .collect { mcpServerConfigs ->
                    runCatching {
                        Log.i(TAG, "update configs: $mcpServerConfigs")
                        val newConfigs = mcpServerConfigs.filter { it.commonOptions.enable }
                        val currentConfigs = clients.keys.toList()
                        val (toAdd, toRemove) = currentConfigs.checkDifferent(
                            other = newConfigs,
                            eq = { a, b -> a.id == b.id }
                        )
                        Log.i(TAG, "to_add: $toAdd")
                        Log.i(TAG, "to_remove: $toRemove")
                        toAdd.forEach { cfg ->
                            appScope.launch {
                                runCatching { addClient(cfg) }
                                    .onFailure { it.printStackTrace() }
                            }
                        }
                        toRemove.forEach { cfg ->
                            appScope.launch { removeClient(cfg) }
                        }
                    }.onFailure {
                        it.printStackTrace()
                    }
                }
        }

        // Reconnect a server as soon as it finishes OAuth sign-in. This is independent of any
        // UI being on screen: after the browser hands the user back, the token lands in the
        // store and McpOAuthManager flips the server's status to Authorized — we pick that up
        // here and (re)connect with the fresh bearer token. Guarded so an already-connected
        // server (e.g. after a routine token refresh) isn't needlessly torn down.
        appScope.launch {
            oauthManager.status.collect { statuses ->
                statuses.forEach { (serverId, oauthStatus) ->
                    if (oauthStatus !is McpOAuthStatus.Authorized) return@forEach
                    val uuid = runCatching { Uuid.parse(serverId) }.getOrNull() ?: return@forEach
                    val server = settingsStore.settingsFlow.value.mcpServers.firstOrNull {
                        it.id == uuid &&
                            it.commonOptions.enable &&
                            it.commonOptions.oauth?.enabled == true
                    } ?: return@forEach
                    val current = syncingStatus.value[uuid]
                    if (current == McpStatus.Connected || current == McpStatus.Connecting) return@forEach
                    appScope.launch {
                        runCatching { addClient(server) }
                            .onFailure { Log.w(TAG, "post-oauth connect failed for ${server.commonOptions.name}", it) }
                    }
                }
            }
        }
    }

    fun getClient(config: McpServerConfig): Client? {
        return clients.entries.find { it.key.id == config.id }?.value
    }

    fun getAllAvailableTools(): List<Pair<Uuid, McpTool>> {
        val settings = settingsStore.settingsFlow.value
        val assistant = settings.getCurrentAssistant()
        return settings.mcpServers
            .filter {
                it.commonOptions.enable && it.id in assistant.mcpServers
            }
            .flatMap { server ->
                server.commonOptions.tools
                    .filter { tool -> tool.enable }
                    .map { tool -> server.id to tool }
            }
    }

    suspend fun callTool(serverId: Uuid, toolName: String, args: JsonObject): JsonElement {
        val entry = clients.entries.find { it.key.id == serverId }
        val client = entry?.value
            ?: return JsonPrimitive("Failed to execute tool, because no such mcp client for the tool")
        val config = entry.key
        Log.i(TAG, "callTool: $toolName / $args (server: ${config.commonOptions.name})")

        if (client.transport == null) client.connect(getTransport(config))
        val result = client.callTool(
            request = CallToolRequest(
                name = toolName,
                arguments = args,
            ),
            options = RequestOptions(timeout = 60.seconds),
            compatibility = true
        )
        require(result != null) {
            "Result is null"
        }
        return McpJson.encodeToJsonElement(result.content)
    }

    // suspend because OAuth-enabled servers need a (possibly refreshed) bearer token resolved
    // before the transport is built. It throws McpOAuthRequiredException when an oauth-enabled
    // server has no valid token; the connect/sync paths turn that into an Error status that
    // prompts the user to sign in from Settings.
    private suspend fun getTransport(config: McpServerConfig): AbstractTransport {
        val resolvedHeaders = resolveHeaders(config)
        return when (config) {
            is McpServerConfig.SseTransportServer -> {
                SseClientTransport(
                    urlString = config.url,
                    client = okHttpClient,
                    headers = resolvedHeaders,
                )
            }

            is McpServerConfig.StreamableHTTPServer -> {
                StreamableHttpClientTransport(
                    url = config.url,
                    client = okHttpClient,
                    headers = resolvedHeaders.toMap(),
                )
            }
        }
    }

    // Combine the user's static headers with an OAuth bearer header when the server opts into
    // OAuth. A throw here (no valid token) surfaces through addClient/sync as an Error status,
    // prompting the user to authorize from Settings. A user-supplied Authorization header takes
    // precedence and disables the automatic bearer to avoid sending two conflicting credentials.
    private suspend fun resolveHeaders(config: McpServerConfig): List<Pair<String, String>> {
        val staticHeaders = config.commonOptions.headers
        val oauth = config.commonOptions.oauth
        if (oauth?.enabled != true) return staticHeaders
        if (staticHeaders.any { it.first.equals("Authorization", ignoreCase = true) }) {
            return staticHeaders
        }
        val token = oauthManager.getValidAccessToken(config.id.toString())
            ?: throw McpOAuthRequiredException(
                context.getString(R.string.mcp_oauth_authorization_required)
            )
        return staticHeaders + ("Authorization" to "Bearer $token")
    }

    suspend fun addClient(config: McpServerConfig) = withContext(Dispatchers.IO) {
        removeClient(config) // Remove first
        val transport = getTransport(config)
        val client = Client(
            clientInfo = Implementation(
                name = config.commonOptions.name,
                version = "1.0",
            )
        )
        clients[config] = client
        runCatching {
            setStatus(config = config, status = McpStatus.Connecting)
            client.connect(transport)
            sync(config)
            setStatus(config = config, status = McpStatus.Connected)
            Log.i(TAG, "addClient: connected ${config.commonOptions.name}")
        }.onFailure {
            it.printStackTrace()
            setStatus(config = config, status = McpStatus.Error(it.message ?: it.javaClass.name))
        }
    }

    private suspend fun sync(config: McpServerConfig) {
        val client = clients[config] ?: return

        setStatus(config = config, status = McpStatus.Connecting)

        // Update tools
        if (client.transport == null) {
            client.connect(getTransport(config))
        }
        val serverTools = client.listTools()?.tools ?: emptyList()
        Log.i(TAG, "sync: tools: $serverTools")
        settingsStore.update { old ->
            old.copy(
                mcpServers = old.mcpServers.map { serverConfig ->
                    if (serverConfig.id != config.id) return@map serverConfig
                    val common = serverConfig.commonOptions
                    val tools = common.tools.toMutableList()

                    // 基于server对比
                    serverTools.forEach { serverTool ->
                        val tool = tools.find { it.name == serverTool.name }
                        if (tool == null) {
                            tools.add(
                                McpTool(
                                    name = serverTool.name,
                                    description = serverTool.description,
                                    enable = true,
                                    inputSchema = serverTool.inputSchema.toSchema()
                                )
                            )
                        } else {
                            val index = tools.indexOf(tool)
                            tools[index] = tool.copy(
                                description = serverTool.description,
                                inputSchema = serverTool.inputSchema.toSchema()
                            )
                        }
                    }

                    // 删除不在server内的
                    tools.removeIf { tool -> serverTools.none { it.name == tool.name } }

                    // 更新clients
                    clients.remove(config)
                    clients.put(
                        config.clone(
                            commonOptions = common.copy(
                                tools = tools
                            )
                        ), client
                    )

                    // 返回新的serverConfig，更新到settings store
                    serverConfig.clone(
                        commonOptions = common.copy(
                            tools = tools
                        )
                    )
                }
            )
        }

        setStatus(config = config, status = McpStatus.Connected)
    }

    suspend fun syncAll() = withContext(Dispatchers.IO) {
        clients.keys.toList().forEach { config ->
            runCatching {
                sync(config)
            }.onFailure {
                it.printStackTrace()
            }
        }
    }

    suspend fun removeClient(config: McpServerConfig) = withContext(Dispatchers.IO) {
        val toRemove = clients.entries.filter { it.key.id == config.id }
        toRemove.forEach { entry ->
            runCatching {
                entry.value.close()
            }.onFailure {
                it.printStackTrace()
            }
            clients.remove(entry.key)
            syncingStatus.emit(syncingStatus.value.toMutableMap().apply { remove(entry.key.id) })
            Log.i(TAG, "removeClient: ${entry.key} / ${entry.key.commonOptions.name}")
        }
    }

    private suspend fun setStatus(config: McpServerConfig, status: McpStatus) {
        syncingStatus.emit(syncingStatus.value.toMutableMap().apply {
            put(config.id, status)
        })
    }

    fun getStatus(config: McpServerConfig): Flow<McpStatus> {
        return syncingStatus.map { it[config.id] ?: McpStatus.Idle }
    }
}

/**
 * Thrown while building a transport for an OAuth-enabled server that has no valid access token
 * (never authorized, or the refresh token was rejected). Caught by the connect/sync paths and
 * turned into an [McpStatus.Error] so the UI can prompt the user to sign in.
 */
class McpOAuthRequiredException(message: String) : Exception(message)

@OptIn(ExperimentalSerializationApi::class)
internal val McpJson: Json by lazy {
    Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        isLenient = true
        classDiscriminatorMode = ClassDiscriminatorMode.NONE
        explicitNulls = false
    }
}

private fun Tool.Input.toSchema(): InputSchema {
    return InputSchema.Obj(properties = this.properties, required = this.required)
}

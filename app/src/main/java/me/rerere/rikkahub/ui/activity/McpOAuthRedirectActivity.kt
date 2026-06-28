package me.rerere.rikkahub.ui.activity

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import me.rerere.rikkahub.RouteActivity

/**
 * Handles the `lastchat://mcp/oauth` deep link the loopback callback page bounces to after an
 * MCP OAuth sign-in completes. The token exchange itself already ran in-process against the
 * loopback server; this activity exists solely to bring the app back to the foreground and
 * land the user back on the MCP settings screen.
 */
class McpOAuthRedirectActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        startActivity(
            Intent(this, RouteActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
                putExtra("openMcpSettings", true)
            }
        )
        finish()
    }
}

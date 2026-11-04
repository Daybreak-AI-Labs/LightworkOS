package dev.maverick

import com.google.gson.JsonElement
import com.google.gson.JsonParser
import java.net.HttpURLConnection
import java.net.URI
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

/** One owned, bounded, read-only request. No redirect, retry, token logging or UI-thread I/O. */
internal class DashboardRequest(private val base: String, private val path: String,
    private val complete: (JsonElement?, String?) -> Unit) : AutoCloseable {
    private val stopped = AtomicBoolean(false)
    private val delivered = AtomicBoolean(false)
    private fun deliver(result: JsonElement?, reason: String?) { if (delivered.compareAndSet(false, true)) complete(result, reason) }
    private val connection = AtomicReference<HttpURLConnection?>(null)
    private val worker = thread(start = false, isDaemon = true, name = "lightwork-dashboard-read") {
        try {
            val token = DashboardSettings.token(base)
            val safeBase = DashboardSettings.validate(base, !token.isNullOrEmpty())
            if (stopped.get()) return@thread
            val conn = URI(safeBase + path).toURL().openConnection() as HttpURLConnection
            connection.set(conn)
            try {
                if (stopped.get()) return@thread
                conn.instanceFollowRedirects = false; conn.connectTimeout = 10_000; conn.readTimeout = 10_000
                conn.setRequestProperty("Accept", "application/json")
                if (!token.isNullOrEmpty()) conn.setRequestProperty("Authorization", "Bearer $token")
                val status = conn.responseCode
                if (status != 200) {
                    val reason = if (status == 401 || status == 403) "Access changed (HTTP $status). Repair the connection in Settings."
                        else "Connection was not confirmed (HTTP $status). Check the address and dashboard availability."
                    if (!stopped.get()) deliver(null, reason)
                    return@thread
                }
                require(conn.contentLengthLong <= 1_048_576) { "Bound" }
                val bytes = conn.inputStream.use { input ->
                    val output = java.io.ByteArrayOutputStream(); val buffer = ByteArray(4096)
                    while (true) {
                        if (stopped.get()) return@thread
                        val count = input.read(buffer); if (count < 0) break
                        require(output.size() + count <= 1_048_576) { "Bound" }; output.write(buffer, 0, count)
                    }
                    output.toByteArray()
                }
                val result = JsonParser.parseString(bytes.toString(Charsets.UTF_8))
                if (!stopped.get()) deliver(result, null)
            } finally { conn.disconnect(); connection.compareAndSet(conn, null) }
        } catch (_: Exception) {
            if (!stopped.get()) deliver(null, "Connection could not be verified. Check Settings, protected credentials and dashboard availability.")
        } finally { stopped.set(true) }
    }
    fun start() {
        worker.start()
        thread(isDaemon = true, name = "lightwork-dashboard-deadline") {
            worker.join(15_000)
            if (worker.isAlive && stopped.compareAndSet(false, true)) {
                deliver(null, "Connection deadline exceeded. Check the dashboard before retrying.")
                connection.get()?.disconnect(); worker.interrupt()
            }
        }
    }
    override fun close() {
        stopped.set(true); worker.interrupt()
        thread(isDaemon = true, name = "lightwork-dashboard-close") { connection.get()?.disconnect() }
    }
}

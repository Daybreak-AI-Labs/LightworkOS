package dev.maverick

import com.google.gson.JsonParser
import java.net.HttpURLConnection
import java.net.URI
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

/** Owned transport; callbacks apply backpressure and reject obsolete UI generations. */
internal class RunEventStream(
    private val endpoint: URI,
    private val token: String?,
    initialCursor: Long,
    private val emit: (String) -> Boolean,
    private val saveCursor: (Long) -> Unit,
    private val timing: Timing = Timing(),
) : AutoCloseable {
    private val stopped = AtomicBoolean(false)
    private val connection = AtomicReference<HttpURLConnection?>(null)
    private val closer = AtomicReference<Thread?>(null)
    private var cursor = initialCursor
    private var worker: Thread? = null

    fun start() {
        check(worker == null)
        worker = thread(isDaemon = true, name = "lightwork-run-watch") { run() }
    }

    fun isAlive(): Boolean = worker?.isAlive == true || closer.get()?.isAlive == true

    override fun close() {
        if (!stopped.compareAndSet(false, true)) return
        worker?.interrupt()
        // Disconnect may wait for a socket operation; never block the IDE event thread.
        val cleanup = Thread({ connection.get()?.disconnect() }, "lightwork-run-close").apply { isDaemon = true }
        closer.set(cleanup)
        cleanup.start()
    }

    private fun run() {
        var backoff = timing.retryMillis
        try {
            while (!stopped.get()) {
                var conn: HttpURLConnection? = null
                try {
                    val uri = URI("$endpoint?since=$cursor")
                    conn = uri.toURL().openConnection() as HttpURLConnection
                    connection.set(conn)
                    if (stopped.get()) return
                    conn.connectTimeout = timing.connectMillis
                    conn.readTimeout = timing.idleMillis // server heartbeat is 30 seconds
                    conn.instanceFollowRedirects = false
                    conn.setRequestProperty("Accept", "text/event-stream")
                    conn.setRequestProperty("Last-Event-ID", cursor.toString())
                    if (!token.isNullOrBlank()) conn.setRequestProperty("Authorization", "Bearer $token")
                    val status = conn.responseCode
                    if (status != 200) {
                        if (status != 429 && status < 500) {
                            emit("[Stream refused: HTTP $status. Check the run, sign-in and permissions.]")
                            return
                        }
                        throw java.io.IOException("temporary HTTP response")
                    }
                    if (!conn.contentType.orEmpty().lowercase().startsWith("text/event-stream")) {
                        emit("[Dashboard returned an unsupported stream response.]")
                        return
                    }
                    java.io.BufferedReader(java.io.InputStreamReader(conn.inputStream, Charsets.UTF_8), 4096).use { reader ->
                        val frame = StringBuilder()
                        var previousCR = false
                        while (!stopped.get()) {
                            val value = reader.read()
                            if (value < 0) break
                            val char = value.toChar()
                            if (char == '\n' && previousCR) { previousCR = false; continue }
                            previousCR = char == '\r'
                            frame.append(if (previousCR) '\n' else char)
                            if (frame.length > MAX_FRAME) { emit("[Stream frame exceeds the client bound.]"); return }
                            if (frame.length >= 2 && frame[frame.length - 1] == '\n' && frame[frame.length - 2] == '\n') {
                                val parsed = parseFrame(frame.toString())
                                frame.setLength(0)
                                when (parsed.kind) {
                                    "heartbeat" -> Unit
                                    "timeout" -> break
                                    "error" -> { emit("[Run visibility changed or its stream is unavailable.]"); return }
                                    "end" -> { emit("[Run complete.]"); return }
                                    else -> if (parsed.id > cursor) {
                                        if (!emit(parsed.data) || stopped.get()) return
                                        cursor = parsed.id
                                        saveCursor(cursor)
                                        backoff = timing.retryMillis
                                    }
                                }
                            }
                        }
                    }
                } catch (_: ProtocolException) {
                    if (!stopped.get()) emit("[Stream acknowledgement is invalid; reopen the dashboard to review this run.]")
                    return
                } catch (_: Exception) {
                    if (stopped.get()) return
                } finally {
                    conn?.disconnect()
                    connection.compareAndSet(conn, null)
                }
                if (!stopped.get()) {
                    if (!emit("[Reconnecting after event $cursor in ${backoff / 1000}s.]")) return
                    Thread.sleep(backoff)
                    backoff = (backoff * 2).coerceAtMost(timing.maxRetryMillis)
                }
            }
        } catch (_: InterruptedException) {
            // Explicit close owns cancellation; no reconnect after replacement/disposal.
        } finally { stopped.set(true) }
    }

    private data class Frame(val kind: String, val id: Long = 0, val data: String = "")
    private class ProtocolException : Exception()

    private fun parseFrame(frame: String): Frame {
        var kind = "message"
        var id = ""
        val data = ArrayList<String>()
        frame.lineSequence().forEach { line ->
            when {
                line.startsWith("event:") -> kind = line.substring(6).trim()
                line.startsWith("id:") -> id = line.substring(3).trim()
                line.startsWith("data:") -> data.add(line.substring(5).removePrefix(" "))
            }
        }
        if (data.isEmpty()) return Frame("heartbeat")
        if (kind == "timeout" || kind == "error") return Frame(kind)
        val text = data.joinToString("\n")
        try {
            val json = JsonParser.parseString(text)
            if (!json.isJsonObject) throw ProtocolException()
            if (kind == "end") {
                val terminal = json.asJsonObject.get("terminal")
                val next = json.asJsonObject.get("next_id")
                if (terminal == null || !terminal.isJsonPrimitive || !terminal.asJsonPrimitive.isBoolean || !terminal.asBoolean ||
                    next == null || !next.isJsonPrimitive || !next.asJsonPrimitive.isNumber ||
                    !next.asString.matches(Regex("[0-9]+")) || next.asString.toLongOrNull() != cursor) throw ProtocolException()
                return Frame("end")
            }
            val number = if (id.matches(Regex("[0-9]+"))) id.toLongOrNull() else null
            if (number == null || number <= 0) throw ProtocolException()
            return Frame(kind, number, text)
        } catch (_: Exception) { throw ProtocolException() }
    }

    companion object {
        private const val MAX_FRAME = 262_144
        fun validEndpoint(uri: URI): Boolean = uri.scheme in setOf("http", "https") &&
            !uri.host.isNullOrBlank() && uri.userInfo == null && uri.query == null && uri.fragment == null
        fun tokenTransportSafe(uri: URI): Boolean = uri.scheme == "https" ||
            uri.host.lowercase() in setOf("127.0.0.1", "localhost", "::1", "[::1]")
    }

    internal data class Timing(val connectMillis: Int = 10_000, val idleMillis: Int = 45_000,
        val retryMillis: Long = 1000L, val maxRetryMillis: Long = 30_000L) {
        init { require(connectMillis > 0 && idleMillis > 0 && retryMillis > 0 && maxRetryMillis >= retryMillis) }
    }
}

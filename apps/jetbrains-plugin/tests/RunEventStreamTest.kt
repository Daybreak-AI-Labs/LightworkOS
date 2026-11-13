package dev.maverick

import com.google.gson.JsonParser
import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.net.URI
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** Standalone real JVM/loopback transport acceptance; no IDE or customer dashboard. */
private class Fixture(handler: (HttpExchange, Int) -> Unit) : AutoCloseable {
    val calls = AtomicInteger()
    val lines = ConcurrentLinkedQueue<String>()
    val cursors = ConcurrentLinkedQueue<Long>()
    val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
    private val executor = Executors.newFixedThreadPool(4) { task -> Thread(task).apply { isDaemon = true } }
    var watch: RunEventStream? = null
    init {
        server.executor = executor
        server.createContext("/events") { exchange ->
            try { handler(exchange, calls.incrementAndGet()) } finally { exchange.close() }
        }
        server.start()
    }
    fun start(timing: RunEventStream.Timing = RunEventStream.Timing(retryMillis = 20, maxRetryMillis = 40)) {
        watch = RunEventStream(URI("http://127.0.0.1:${server.address.port}/events"), "fixture-token", 0,
            emit = { lines.add(it); true }, saveCursor = { cursors.add(it) }, timing = timing).also { it.start() }
    }
    fun finished() = eventually { watch?.isAlive() != true }
    override fun close() {
        watch?.close()
        server.stop(0)
        executor.shutdownNow()
        finished()
        check(executor.awaitTermination(3, TimeUnit.SECONDS))
    }
}

private fun eventually(predicate: () -> Boolean) {
    val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(4)
    while (!predicate() && System.nanoTime() < end) Thread.sleep(5)
    check(predicate()) { "owned work did not reach its expected state before deadline" }
}
private fun HttpExchange.stream(text: String) {
    responseHeaders.add("Content-Type", "text/event-stream")
    sendResponseHeaders(200, 0)
    responseBody.write(text.toByteArray())
    responseBody.flush()
}
private fun event(id: Long) = "id: $id\ndata: {\"id\":$id,\"content\":\"event-$id\"}\n\n"
private fun end(cursor: Long) = "event: end\ndata: {\"terminal\":true,\"next_id\":$cursor}\n\n"

fun main() {
    var tests = 0
    val sharedPages = JsonParser.parseString(sharedGoalEventsFixture).asJsonObject.getAsJsonArray("pages")
    val sharedEvents = sharedPages.flatMap { it.asJsonObject.getAsJsonArray("events").toList() }
    val sharedLast = sharedPages.last().asJsonObject
    Fixture { exchange, _ ->
        val frames = sharedEvents.joinToString("") { item ->
            val id = item.asJsonObject.get("id").asLong
            "id: $id\ndata: $item\n\n"
        }
        val cursor = sharedLast.get("next_id").asLong
        val terminal = "event: end\ndata: {\"terminal\":true,\"next_id\":$cursor}\n\n"
        exchange.stream(frames + terminal)
    }.use { f ->
        f.start(); f.finished()
        check(f.cursors.toList() == listOf(1L, 2L, 3L) && f.lines.last() == "[Run complete.]")
        tests++
    }
    Fixture { exchange, _ -> exchange.stream((1L..401L).joinToString("") { event(it) } + end(401)) }.use { f ->
        f.start(); f.finished()
        check(f.lines.count { it.startsWith("{") } == 401)
        check(f.cursors.last() == 401L && f.lines.count { it == "[Run complete.]" } == 1)
        check(f.calls.get() == 1); tests++
    }
    Fixture { exchange, number ->
        when (number) {
            1 -> { check(exchange.requestURI.query == "since=0"); exchange.stream(event(17)) }
            2 -> {
                check(exchange.requestURI.query == "since=17")
                check(exchange.requestHeaders.getFirst("Last-Event-ID") == "17")
                exchange.stream(event(17) + event(21) + "event: timeout\ndata: {}\n\n")
            }
            else -> { check(exchange.requestURI.query == "since=21"); exchange.stream(end(21)) }
        }
    }.use { f ->
        f.start(); f.finished()
        check(f.cursors.toList() == listOf(17L, 21L) && f.calls.get() == 3); tests++
    }
    for (status in listOf(401, 403, 404, 302)) {
        Fixture { exchange, _ -> exchange.sendResponseHeaders(status, -1) }.use { f ->
            f.start(); f.finished()
            check(f.calls.get() == 1 && f.lines.single().contains("HTTP $status")); tests++
        }
    }
    Fixture { exchange, _ ->
        exchange.stream(": heartbeat\n\n")
        repeat(6) {
            Thread.sleep(40)
            exchange.responseBody.write(": heartbeat\n\n".toByteArray()); exchange.responseBody.flush()
        }
        exchange.responseBody.write(end(0).toByteArray()); exchange.responseBody.flush()
    }.use { f ->
        f.start(RunEventStream.Timing(idleMillis = 150, retryMillis = 20, maxRetryMillis = 40)); f.finished()
        check(f.calls.get() == 1 && f.lines.last() == "[Run complete.]"); tests++
    }
    Fixture { exchange, number ->
        exchange.stream(if (number == 1) ": heartbeat\n\n" else end(0))
        if (number == 1) Thread.sleep(500)
    }.use { f ->
        f.start(RunEventStream.Timing(idleMillis = 100, retryMillis = 20, maxRetryMillis = 40)); f.finished()
        check(f.calls.get() == 2); tests++
    }
    val connected = CountDownLatch(1)
    Fixture { exchange, _ ->
        exchange.stream(": heartbeat\n\n"); connected.countDown(); Thread.sleep(30_000)
    }.use { f ->
        f.start(); check(connected.await(2, TimeUnit.SECONDS))
        f.watch!!.close(); f.finished()
        val count = f.lines.size
        Thread.sleep(50)
        check(f.lines.size == count && f.calls.get() == 1); tests++
    }
    for (wire in listOf("x".repeat(262_145), "event: end\ndata: {\"terminal\":true,\"next_id\":9}\n\n")) {
        Fixture { exchange, _ -> exchange.stream(wire) }.use { f ->
            f.start(); f.finished()
            check(f.lines.none { it == "[Run complete.]" } && f.calls.get() == 1)
            check(f.lines.single().contains("bound") || f.lines.single().contains("invalid")); tests++
        }
    }
    Fixture { exchange, _ ->
        exchange.stream("")
        val bytes = (event(7).replace("id: 7\n", "id: 7\nevent: error\n").replace("event-7", "café").replace("\n", "\r\n") + end(7)).toByteArray()
        for (byte in bytes) { exchange.responseBody.write(byte.toInt()); exchange.responseBody.flush() }
    }.use { f ->
        f.start(); f.finished()
        check(f.lines.any { it.contains("café") } && f.cursors.last() == 7L); tests++
    }
    println("$tests JVM transport cases passed; no IDE lifecycle qualification implied.")
}

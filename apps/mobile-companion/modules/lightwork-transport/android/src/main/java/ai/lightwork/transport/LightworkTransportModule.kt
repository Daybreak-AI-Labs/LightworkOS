package ai.lightwork.transport

import expo.modules.kotlin.Promise
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import okhttp3.Call
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.ByteArrayOutputStream
import java.net.URI
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** No redirects, ambient cookies, disk cache or unbounded bridge response. */
class LightworkTransportModule : Module() {
  private val lock = Any()
  private val calls = mutableMapOf<String, Call>()
  private val cancelled = LinkedHashMap<String, Long>()
  private val workers = Executors.newFixedThreadPool(2)
  private val client = OkHttpClient.Builder().followRedirects(false).followSslRedirects(false)
    .retryOnConnectionFailure(false).callTimeout(15, TimeUnit.SECONDS)
    .connectTimeout(10, TimeUnit.SECONDS).readTimeout(10, TimeUnit.SECONDS).build()

  override fun definition() = ModuleDefinition {
    Name("LightworkTransport")
    AsyncFunction("request") { id: String, url: String, method: String, headers: Map<String, String>, body: String?, promise: Promise ->
      try {
        val uri = URI(url)
        val host = uri.host?.trim('[', ']')?.lowercase()
        val safe = uri.scheme == "https" || (uri.scheme == "http" && host in setOf("localhost", "127.0.0.1", "::1"))
        require(safe && !host.isNullOrEmpty() && uri.userInfo == null && uri.fragment == null)
        require(method in setOf("GET", "POST") && id.length in 1..80 && (body?.toByteArray()?.size ?: 0) <= 65536)
        val builder = Request.Builder().url(url).method(method, if (method == "POST") (body ?: "").toRequestBody() else null)
        for ((key, value) in headers) {
          require(key.lowercase() in setOf("accept", "authorization", "content-type", "origin", "x-lightwork-expected-tenant", "x-lightwork-offline-policy"))
          require(value.length <= 16384 && !value.contains('\r') && !value.contains('\n'))
          builder.header(key, value)
        }
        val call = client.newCall(builder.build())
        synchronized(lock) {
          cancelled.entries.removeAll { System.currentTimeMillis() - it.value > 30000 }
          if (cancelled.remove(id) != null) { promise.reject("E_CANCELLED", "Request cancelled", null); return@AsyncFunction }
          require(calls.size < 4 && !calls.containsKey(id))
          calls[id] = call
        }
        workers.execute {
          try {
            call.execute().use { response ->
              if (response.code in 300..399) { promise.reject("E_REDIRECT", "Redirect refused", null); return@use }
              if (response.code !in 200..299) { promise.resolve(mapOf("status" to response.code, "body" to "")); return@use }
              val responseBody = response.body ?: error("Missing body")
              if (responseBody.contentLength() > LIMIT) { promise.reject("E_TOO_LARGE", "Response limit exceeded", null); return@use }
              val output = ByteArrayOutputStream()
              responseBody.byteStream().use { input ->
                val chunk = ByteArray(8192)
                while (true) {
                  val count = input.read(chunk)
                  if (count == -1) break
                  if (output.size() + count > LIMIT) { call.cancel(); promise.reject("E_TOO_LARGE", "Response limit exceeded", null); return@execute }
                  output.write(chunk, 0, count)
                }
              }
              // Only the task list's continuation headers cross into JavaScript.
              val exposed = RESPONSE_HEADERS.mapNotNull { name -> response.header(name)?.takeIf { it.length <= 32 }?.let { name to it } }.toMap()
              if (call.isCanceled()) promise.reject("E_CANCELLED", "Request cancelled", null)
              else promise.resolve(mapOf("status" to response.code, "body" to output.toString("UTF-8"), "headers" to exposed))
            }
          } catch (_: Exception) {
            promise.reject(if (call.isCanceled()) "E_CANCELLED" else "E_NETWORK", "Request did not complete", null)
          } finally { synchronized(lock) { calls.remove(id) } }
        }
      } catch (_: Exception) { synchronized(lock) { calls.remove(id)?.cancel() }; promise.reject("E_REQUEST", "Request unavailable", null) }
    }
    Function("cancel") { id: String ->
      synchronized(lock) {
        calls[id]?.cancel()
        cancelled[id] = System.currentTimeMillis()
        while (cancelled.size > 100) cancelled.remove(cancelled.keys.first())
      }
    }
    OnDestroy {
      synchronized(lock) { calls.values.forEach { it.cancel() }; calls.clear(); cancelled.clear() }
      workers.shutdownNow()
      client.connectionPool.evictAll()
    }
  }

  companion object {
    private const val LIMIT = 4 * 1024 * 1024
    private val RESPONSE_HEADERS = listOf("pagination-has-more", "pagination-next-before-id")
  }
}

import ExpoModulesCore
import Foundation

private final class BoundedRequest: NSObject, URLSessionDataDelegate {
  static let limit = 4 * 1024 * 1024
  // Only the task list's continuation headers cross into JavaScript.
  static let responseHeaders = ["pagination-has-more", "pagination-next-before-id"]
  private let promise: Promise
  private let finished: () -> Void
  private let lock = NSLock()
  private var closed = false
  private var bytes = Data()
  private var status = 0
  private var headers: [String: String] = [:]
  private var session: URLSession?
  private var task: URLSessionDataTask?

  init(promise: Promise, finished: @escaping () -> Void) { self.promise = promise; self.finished = finished }
  func start(_ request: URLRequest) {
    lock.lock(); defer { lock.unlock() }
    guard !closed else { return }
    let config = URLSessionConfiguration.ephemeral
    config.httpCookieStorage = nil; config.httpShouldSetCookies = false
    config.urlCache = nil; config.requestCachePolicy = .reloadIgnoringLocalCacheData
    config.timeoutIntervalForRequest = 10; config.timeoutIntervalForResource = 15
    let session = URLSession(configuration: config, delegate: self, delegateQueue: nil)
    self.session = session; task = session.dataTask(with: request); task?.resume()
  }
  func cancel() { finish("E_CANCELLED") }
  private func finish(_ code: String? = nil) {
    lock.lock()
    guard !closed else { lock.unlock(); return }
    closed = true
    let body = String(data: bytes, encoding: .utf8)
    let status = status, headers = headers
    bytes.removeAll(); let session = session; self.session = nil; task = nil
    lock.unlock()
    session?.invalidateAndCancel(); finished()
    if let code { promise.reject(code, "Request did not complete") }
    else if let body { promise.resolve(["status": status, "body": body, "headers": headers]) }
    else { promise.reject("E_RESPONSE", "Response was not UTF-8") }
  }
  func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                  newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
    completionHandler(nil); finish("E_REDIRECT")
  }
  func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                  completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
    guard let response = response as? HTTPURLResponse else { completionHandler(.cancel); finish("E_RESPONSE"); return }
    lock.lock(); status = response.statusCode; lock.unlock()
    if (300..<400).contains(response.statusCode) { completionHandler(.cancel); finish("E_REDIRECT"); return }
    if !(200..<300).contains(response.statusCode) { completionHandler(.cancel); finish(); return }
    if response.expectedContentLength > Int64(Self.limit) { completionHandler(.cancel); finish("E_TOO_LARGE"); return }
    var exposed: [String: String] = [:]
    for name in Self.responseHeaders {
      if let value = response.value(forHTTPHeaderField: name), value.utf8.count <= 32 { exposed[name] = value }
    }
    lock.lock(); headers = exposed; lock.unlock()
    completionHandler(.allow)
  }
  func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
    lock.lock()
    guard !closed else { lock.unlock(); return }
    if bytes.count + data.count > Self.limit { lock.unlock(); finish("E_TOO_LARGE"); return }
    bytes.append(data); lock.unlock()
  }
  func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
    finish(error == nil ? nil : "E_NETWORK")
  }
}

public final class LightworkTransportModule: Module {
  private let lock = NSLock()
  private var requests: [String: BoundedRequest] = [:]
  private var cancelled: [String: Date] = [:]
  public func definition() -> ModuleDefinition {
    Name("LightworkTransport")
    AsyncFunction("request") { (id: String, url: String, method: String, headers: [String: String], body: String?, promise: Promise) in
      guard let target = URL(string: url), let host = target.host?.lowercased(),
        target.user == nil, target.password == nil, target.fragment == nil,
        target.scheme == "https" || (target.scheme == "http" && ["localhost", "127.0.0.1", "::1", "[::1]"].contains(host)),
        ["GET", "POST"].contains(method), !id.isEmpty, id.count <= 80,
        (body?.utf8.count ?? 0) <= 65536 else { promise.reject("E_REQUEST", "Request unavailable"); return }
      var request = URLRequest(url: target)
      request.httpMethod = method; request.httpBody = method == "POST" ? (body ?? "").data(using: .utf8) : nil
      for (key, value) in headers {
        guard ["accept", "authorization", "content-type", "origin", "x-lightwork-expected-tenant", "x-lightwork-offline-policy"].contains(key.lowercased()),
          value.utf8.count <= 16384, !value.contains("\r"), !value.contains("\n") else {
          promise.reject("E_REQUEST", "Request unavailable"); return
        }
        request.setValue(value, forHTTPHeaderField: key)
      }
      self.lock.lock()
      self.cancelled = self.cancelled.filter { Date().timeIntervalSince($0.value) < 30 }
      if self.cancelled.removeValue(forKey: id) != nil { self.lock.unlock(); promise.reject("E_CANCELLED", "Request cancelled"); return }
      guard self.requests.count < 4, self.requests[id] == nil else { self.lock.unlock(); promise.reject("E_BUSY", "Request limit reached"); return }
      let active = BoundedRequest(promise: promise) { [weak self] in
        guard let self else { return }
        self.lock.lock(); self.requests.removeValue(forKey: id); self.lock.unlock()
      }
      self.requests[id] = active; self.lock.unlock(); active.start(request)
    }
    Function("cancel") { (id: String) in
      self.lock.lock(); let active = self.requests[id]
      self.cancelled[id] = Date()
      if self.cancelled.count > 100, let oldest = self.cancelled.min(by: { $0.value < $1.value })?.key { self.cancelled.removeValue(forKey: oldest) }
      self.lock.unlock(); active?.cancel()
    }
    OnDestroy {
      self.lock.lock(); let active = Array(self.requests.values); self.requests.removeAll(); self.cancelled.removeAll(); self.lock.unlock()
      active.forEach { $0.cancel() }
    }
  }
}

import Foundation

@main
struct PreferenceChoiceTest {
    static func main() throws {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        let expiries: [Int?] = [nil, 1_900_000_000]
        for expiry in expiries {
            let choice = PreferenceChoice(purposeID: "analytics", action: "grant",
                                          channel: "web", vendorID: "all", expiresAt: expiry)
            let encoded = try encoder.encode(choice)
            let payload = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
            precondition(payload.count == 5)
            if let expiry {
                precondition(payload["expires_at"] as? Int == expiry)
            } else {
                precondition(payload["expires_at"] is NSNull)
            }
        }
        print("Preference expiry encoding matches the server contract.")
    }
}

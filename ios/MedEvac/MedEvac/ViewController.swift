import UIKit
import WebKit

class ViewController: UIViewController, WKNavigationDelegate, WKUIDelegate {

    private var webView: WKWebView!
    private var splashView: UIView!
    private var offlineBanner: UILabel!
    private let hostURL = "https://unit-e-1d07b.web.app"

    // MARK: - Lifecycle

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = UIColor(red: 0.039, green: 0.059, blue: 0.118, alpha: 1.0) // #0a0f1e

        setupWebView()
        setupSplashScreen()
        setupOfflineBanner()
        loadApp()
    }

    override var preferredStatusBarStyle: UIStatusBarStyle { .lightContent }
    override var prefersHomeIndicatorAutoHidden: Bool { true }

    // MARK: - WebView Setup

    private func setupWebView() {
        let config = WKWebViewConfiguration()
        config.allowsInlineMediaPlayback = true
        config.mediaTypesRequiringUserActionForPlayback = []

        // Allow service worker and local storage
        config.websiteDataStore = .default()
        config.preferences.javaScriptCanOpenWindowsAutomatically = false

        // User agent suffix so the web app can detect native wrapper
        config.applicationNameForUserAgent = "MedEvac-iOS"

        webView = WKWebView(frame: view.bounds, configuration: config)
        webView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        webView.navigationDelegate = self
        webView.uiDelegate = self
        webView.scrollView.bounces = true
        webView.scrollView.contentInsetAdjustmentBehavior = .always
        webView.isOpaque = false
        webView.backgroundColor = .clear
        webView.scrollView.backgroundColor = .clear
        webView.allowsBackForwardNavigationGestures = false

        // Pull to refresh
        let refreshControl = UIRefreshControl()
        refreshControl.tintColor = .white
        refreshControl.addTarget(self, action: #selector(pullToRefresh), for: .valueChanged)
        webView.scrollView.refreshControl = refreshControl

        view.addSubview(webView)

        // Safe area constraints
        webView.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            webView.topAnchor.constraint(equalTo: view.topAnchor),
            webView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            webView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            webView.trailingAnchor.constraint(equalTo: view.trailingAnchor)
        ])
    }

    // MARK: - Splash Screen

    private func setupSplashScreen() {
        splashView = UIView(frame: view.bounds)
        splashView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        splashView.backgroundColor = UIColor(red: 0.039, green: 0.059, blue: 0.118, alpha: 1.0)

        let stack = UIStackView()
        stack.axis = .vertical
        stack.alignment = .center
        stack.spacing = 16
        stack.translatesAutoresizingMaskIntoConstraints = false

        // App icon placeholder
        let iconLabel = UILabel()
        iconLabel.text = "+"
        iconLabel.font = UIFont.systemFont(ofSize: 48, weight: .bold)
        iconLabel.textColor = UIColor(red: 0.31, green: 0.43, blue: 0.97, alpha: 1.0) // #4f6ef7
        iconLabel.textAlignment = .center

        let titleLabel = UILabel()
        titleLabel.text = "MedEvac"
        titleLabel.font = UIFont.systemFont(ofSize: 28, weight: .bold)
        titleLabel.textColor = .white

        let spinner = UIActivityIndicatorView(style: .medium)
        spinner.color = .white
        spinner.startAnimating()

        stack.addArrangedSubview(iconLabel)
        stack.addArrangedSubview(titleLabel)
        stack.addArrangedSubview(spinner)

        splashView.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.centerXAnchor.constraint(equalTo: splashView.centerXAnchor),
            stack.centerYAnchor.constraint(equalTo: splashView.centerYAnchor)
        ])

        view.addSubview(splashView)
    }

    private func hideSplash() {
        UIView.animate(withDuration: 0.3) {
            self.splashView.alpha = 0
        } completion: { _ in
            self.splashView.removeFromSuperview()
        }
    }

    // MARK: - Offline Banner

    private func setupOfflineBanner() {
        offlineBanner = UILabel()
        offlineBanner.text = "No Internet Connection"
        offlineBanner.textColor = .white
        offlineBanner.backgroundColor = UIColor.systemRed.withAlphaComponent(0.9)
        offlineBanner.textAlignment = .center
        offlineBanner.font = UIFont.systemFont(ofSize: 14, weight: .medium)
        offlineBanner.isHidden = true
        offlineBanner.translatesAutoresizingMaskIntoConstraints = false

        view.addSubview(offlineBanner)
        NSLayoutConstraint.activate([
            offlineBanner.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            offlineBanner.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            offlineBanner.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            offlineBanner.heightAnchor.constraint(equalToConstant: 32)
        ])
    }

    // MARK: - Loading

    private func loadApp() {
        // Try loading from hosted URL first (gets latest version + service worker)
        if let url = URL(string: hostURL) {
            webView.load(URLRequest(url: url, cachePolicy: .returnCacheDataElseLoad))
        }
    }

    private func loadLocalFallback() {
        // Fallback to bundled HTML if network fails
        if let htmlPath = Bundle.main.path(forResource: "index", ofType: "html") {
            let htmlURL = URL(fileURLWithPath: htmlPath)
            webView.loadFileURL(htmlURL, allowingReadAccessTo: htmlURL.deletingLastPathComponent())
        }
    }

    @objc private func pullToRefresh() {
        webView.reload()
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
            self.webView.scrollView.refreshControl?.endRefreshing()
        }
    }

    // MARK: - WKNavigationDelegate

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        hideSplash()
        offlineBanner.isHidden = true

        // Inject viewport meta for safe areas
        let safeAreaCSS = """
        (function() {
            var meta = document.querySelector('meta[name=viewport]');
            if (meta && !meta.content.includes('viewport-fit')) {
                meta.content += ', viewport-fit=cover';
            }
            document.body.style.paddingTop = 'env(safe-area-inset-top)';
            document.body.style.paddingBottom = 'env(safe-area-inset-bottom)';
        })();
        """
        webView.evaluateJavaScript(safeAreaCSS, completionHandler: nil)
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        handleLoadError(error)
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        handleLoadError(error)
    }

    private func handleLoadError(_ error: Error) {
        let nsError = error as NSError
        // NSURLErrorNotConnectedToInternet or NSURLErrorTimedOut
        if nsError.domain == NSURLErrorDomain &&
            (nsError.code == NSURLErrorNotConnectedToInternet ||
             nsError.code == NSURLErrorTimedOut ||
             nsError.code == NSURLErrorCannotConnectToHost) {
            offlineBanner.isHidden = false
            loadLocalFallback()
        }
    }

    // Block external navigation (stay in-app)
    func webView(_ webView: WKWebView,
                 decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let url = navigationAction.request.url else {
            decisionHandler(.cancel)
            return
        }

        let host = url.host ?? ""
        // Allow our host, firebase, google APIs, and local files
        if url.isFileURL ||
            host.contains("unit-e-1d07b.web.app") ||
            host.contains("firebaseio.com") ||
            host.contains("googleapis.com") ||
            host.contains("gstatic.com") ||
            host.contains("google.com") {
            decisionHandler(.allow)
        } else if navigationAction.navigationType == .linkActivated {
            // Open external links in Safari
            UIApplication.shared.open(url)
            decisionHandler(.cancel)
        } else {
            decisionHandler(.allow)
        }
    }
}

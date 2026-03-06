import UIKit
import WebKit

class ViewController: UIViewController, WKNavigationDelegate, WKUIDelegate, UIScrollViewDelegate {

    private var webView: WKWebView!
    private var splashView: UIView!
    private var offlineBanner: UILabel!
    private let hostURL = "https://unit-e-1d07b.web.app"

    // MARK: - Lifecycle

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = UIColor(red: 0.031, green: 0.043, blue: 0.078, alpha: 1.0)

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
        config.websiteDataStore = .default()
        config.preferences.javaScriptCanOpenWindowsAutomatically = false
        config.applicationNameForUserAgent = "MedEvac-iOS"

        // GPU acceleration & performance
        let prefs = WKWebpagePreferences()
        prefs.allowsContentJavaScript = true
        config.defaultWebpagePreferences = prefs

        webView = WKWebView(frame: view.bounds, configuration: config)
        webView.navigationDelegate = self
        webView.uiDelegate = self
        webView.scrollView.delegate = self

        // Smooth scrolling
        webView.scrollView.bounces = true
        webView.scrollView.alwaysBounceVertical = true
        webView.scrollView.contentInsetAdjustmentBehavior = .always
        webView.scrollView.decelerationRate = .normal
        webView.scrollView.showsVerticalScrollIndicator = false
        webView.scrollView.showsHorizontalScrollIndicator = false

        // Rendering
        webView.isOpaque = true
        webView.backgroundColor = UIColor(red: 0.031, green: 0.043, blue: 0.078, alpha: 1.0)
        webView.scrollView.backgroundColor = UIColor(red: 0.031, green: 0.043, blue: 0.078, alpha: 1.0)
        webView.allowsBackForwardNavigationGestures = false

        // Prevent overscroll rubber-banding on horizontal axis
        webView.scrollView.alwaysBounceHorizontal = false

        // Pull to refresh
        let refreshControl = UIRefreshControl()
        refreshControl.tintColor = .white
        refreshControl.addTarget(self, action: #selector(pullToRefresh), for: .valueChanged)
        webView.scrollView.refreshControl = refreshControl

        view.addSubview(webView)

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
        splashView.backgroundColor = UIColor(red: 0.031, green: 0.043, blue: 0.078, alpha: 1.0)

        let stack = UIStackView()
        stack.axis = .vertical
        stack.alignment = .center
        stack.spacing = 16
        stack.translatesAutoresizingMaskIntoConstraints = false

        let iconLabel = UILabel()
        iconLabel.text = "+"
        iconLabel.font = UIFont.systemFont(ofSize: 48, weight: .bold)
        iconLabel.textColor = UIColor(red: 0.31, green: 0.43, blue: 0.97, alpha: 1.0)
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
        UIView.animate(withDuration: 0.4, delay: 0, options: .curveEaseOut) {
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
        if let url = URL(string: hostURL) {
            var request = URLRequest(url: url, cachePolicy: .returnCacheDataElseLoad)
            request.timeoutInterval = 15
            webView.load(request)
        }
    }

    private func loadLocalFallback() {
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

        // Performance & smoothness optimizations injected into the web page
        let injectCSS = """
        (function() {
            // Viewport fit for safe areas
            var meta = document.querySelector('meta[name=viewport]');
            if (meta && !meta.content.includes('viewport-fit')) {
                meta.content += ', viewport-fit=cover';
            }

            // Safe area padding
            document.body.style.paddingTop = 'env(safe-area-inset-top)';
            document.body.style.paddingBottom = 'env(safe-area-inset-bottom)';

            // Smoothness: GPU-accelerated scrolling, touch optimizations
            var s = document.createElement('style');
            s.textContent = `
                * { -webkit-tap-highlight-color: transparent; }
                html, body { -webkit-overflow-scrolling: touch; }
                .slist, .sp { -webkit-overflow-scrolling: touch; scroll-behavior: smooth; }
                .screen, .pc, .ucard, .ubtn, .btn, .ibtn, .stat, .co {
                    -webkit-transform: translateZ(0);
                    transform: translateZ(0);
                    will-change: transform;
                }
                .pc, .ubtn, .btn, .ibtn {
                    transition: transform 0.15s cubic-bezier(0.25, 0.46, 0.45, 0.94), opacity 0.15s ease !important;
                }
                .pc:active, .ubtn:active, .btn:active, .ibtn:active {
                    transform: translateZ(0) scale(0.97) !important;
                }
                @keyframes fi {
                    from { opacity: 0; transform: translateZ(0) translateY(6px); }
                    to { opacity: 1; transform: translateZ(0) translateY(0); }
                }
            `;
            document.head.appendChild(s);
        })();
        """
        webView.evaluateJavaScript(injectCSS, completionHandler: nil)
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        handleLoadError(error)
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        handleLoadError(error)
    }

    private func handleLoadError(_ error: Error) {
        let nsError = error as NSError
        if nsError.domain == NSURLErrorDomain &&
            (nsError.code == NSURLErrorNotConnectedToInternet ||
             nsError.code == NSURLErrorTimedOut ||
             nsError.code == NSURLErrorCannotConnectToHost) {
            offlineBanner.isHidden = false
            loadLocalFallback()
        }
    }

    // Block external navigation
    func webView(_ webView: WKWebView,
                 decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let url = navigationAction.request.url else {
            decisionHandler(.cancel)
            return
        }

        let host = url.host ?? ""
        if url.isFileURL ||
            host.contains("unit-e-1d07b.web.app") ||
            host.contains("firebaseio.com") ||
            host.contains("firebasedatabase.app") ||
            host.contains("googleapis.com") ||
            host.contains("gstatic.com") ||
            host.contains("google.com") {
            decisionHandler(.allow)
        } else if navigationAction.navigationType == .linkActivated {
            UIApplication.shared.open(url)
            decisionHandler(.cancel)
        } else {
            decisionHandler(.allow)
        }
    }

    // MARK: - UIScrollViewDelegate

    func scrollViewDidScroll(_ scrollView: UIScrollView) {
        // Prevent horizontal scrolling
        if scrollView.contentOffset.x != 0 {
            scrollView.contentOffset.x = 0
        }
    }
}

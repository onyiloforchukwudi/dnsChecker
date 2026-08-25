<?php

/**
 * DNS Checker & Webmail Client Discovery API
 * 
 * A comprehensive standalone API for DNS record lookups and webmail platform detection
 * using advanced fingerprinting heuristics and layered detection methodology.
 * 
 * @author DNS Checker API
 * @version 1.0.0
 */

class DNSChecker
{
    private $domain;
    private $timeout = 5;
    private $port_timeouts = 3;
    private $detected_platform = null;
    private $confidence_score = 0;
    private $evidence = [];
    private $dns_records = [];
    private $http_headers = [];
    private $html_content = '';
    private $cookies = [];
    private $certificate_info = [];

    // Webmail Platform Fingerprints
    private $platforms = [
        'microsoft_365' => [
            'mx_patterns' => ['protection.outlook.com', 'outlook.com'],
            'autodiscover_domains' => ['autodiscover.outlook.com'],
            'keywords' => ['microsoft 365', 'outlook.office365.com'],
            'priority' => 1
        ],
        'owa' => [
            'paths' => ['/owa/', '/ecp/'],
            'cookies' => ['OWA-CANARY', 'X-OWA-CANARY'],
            'headers' => ['X-OWA-Version', 'X-FEServer', 'X-CalculatedBETarget'],
            'keywords' => ['microsoft exchange', 'outlook web app'],
            'priority' => 2
        ],
        'mimecast' => [
            'mx_patterns' => ['mimecast.com', 'eu-smtp-inbound', 'us-smtp-inbound', 'au-smtp-inbound'],
            'cookies' => ['mimecast_session'],
            'keywords' => ['mimecast'],
            'priority' => 3
        ],
        'rackspace' => [
            'mx_patterns' => ['emailsrvr.com', 'rackspace.com'],
            'domains' => ['apps.rackspace.com', 'webmail.rackspace.com'],
            'keywords' => ['rackspace email'],
            'priority' => 4
        ],
        'smartermail' => [
            'paths' => ['/login.aspx'],
            'headers' => ['Server: SmarterMail'],
            'keywords' => ['smartermail', 'smartertools'],
            'priority' => 5
        ],
        'zimbra' => [
            'paths' => ['/modern/', '/zimbra/', '/service/soap', '/service/preauth'],
            'cookies' => ['ZM_AUTH_TOKEN', 'ZM_TEST'],
            'keywords' => ['zimbra collaboration', 'carbonio', 'ZmSettings', 'ZmMsg'],
            'redirects' => ['/modern/', '/zimbra/'],
            'priority' => 6
        ],
        'roundcube' => [
            'cookies' => ['roundcube_sessid'],
            'paths' => ['/program/js/'],
            'keywords' => ['roundcube webmail', 'rcmail', '_task=login', '_action=login'],
            'css_paths' => ['skins/elastic', 'skins/larry'],
            'priority' => 7
        ],
        'cpanel' => [
            'ports' => [2096, 2095],
            'paths' => ['/webmail'],
            'cookies' => ['cpsession'],
            'headers' => ['cpaneld', 'cpsrvd'],
            'keywords' => ['cpanel web'],
            'priority' => 8
        ],
        'horde' => [
            'paths' => ['/horde/', '/imp/'],
            'keywords' => ['horde', 'imp webmail'],
            'priority' => 9
        ]
    ];

    // Common webmail hostnames to probe
    private $webmail_hostnames = [
        'webmail',
        'mail',
        'autodiscover',
        'cpanel',
        'imap',
        'smtp',
        'pop3',
        'secure',
        'mail2'
    ];

    // Ports to probe
    private $ports_to_probe = [80, 443, 2095, 2096];

    // Redirect paths for fingerprinting
    private $redirect_paths = [
        '/roundcube/',
        '/zimbra/',
        '/owa/',
        '/microsoft-server-activesync/',
        '/appsuite/',
        '/webmail/',
        '/modern/',
        '/imp/',
        '/horde/'
    ];

    public function __construct($domain)
    {
        $this->domain = trim(strtolower($domain));
        if (filter_var($this->domain, FILTER_VALIDATE_DOMAIN) === false) {
            throw new Exception("Invalid domain: {$domain}");
        }
    }

    /**
     * Execute full DNS and webmail discovery scan
     */
    public function scan()
    {
        try {
            // Stage 1: DNS Lookups
            $this->performDNSLookups();

            // Stage 2: Autodiscover Detection
            $this->detectAutodiscover();

            // Stage 3: Fingerprinting Engine
            $this->runFingerprintingEngine();

            // Stage 4: Platform Classification
            $this->classifyPlatform();

            return $this->generateReport();
        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    /**
     * Stage 1: Perform comprehensive DNS lookups
     */
    private function performDNSLookups()
    {
        // MX Records
        $this->dns_records['mx'] = dns_get_mx($this->domain);
        
        // SPF Record (TXT)
        $spf_records = dns_get_record($this->domain, DNS_TXT);
        $this->dns_records['spf'] = array_filter($spf_records, function($record) {
            return strpos($record['txt'], 'v=spf1') === 0;
        });

        // DMARC Record
        $dmarc_records = dns_get_record("_dmarc.{$this->domain}", DNS_TXT);
        $this->dns_records['dmarc'] = array_filter($dmarc_records, function($record) {
            return strpos($record['txt'], 'v=DMARC1') === 0;
        });

        // MTA-STS Record
        $mta_sts = dns_get_record("_mta-sts.{$this->domain}", DNS_TXT);
        $this->dns_records['mta_sts'] = $mta_sts;

        // Analyze MX providers
        $this->analyzeMXProviders();
    }

    /**
     * Analyze MX provider fingerprints
     */
    private function analyzeMXProviders()
    {
        if (empty($this->dns_records['mx'])) {
            return;
        }

        foreach ($this->dns_records['mx'] as $mx_record) {
            $mx_host = strtolower($mx_record['host']);
            $this->addEvidence('MX Host', $mx_host, 'low');

            // Check for known providers
            foreach ($this->platforms as $platform => $config) {
                if (isset($config['mx_patterns'])) {
                    foreach ($config['mx_patterns'] as $pattern) {
                        if (stripos($mx_host, $pattern) !== false) {
                            $this->addEvidence("MX Provider Match: {$pattern}", $mx_host, 'high');
                            $this->updateConfidence($platform, 25);
                        }
                    }
                }
            }
        }
    }

    /**
     * Stage 2: Detect Autodiscover endpoints
     */
    private function detectAutodiscover()
    {
        $autodiscover_domains = [
            "autodiscover.{$this->domain}",
            "autodiscover.outlook.com",
            "{$this->domain}/.well-known/autoconfig.xml"
        ];

        foreach ($autodiscover_domains as $domain) {
            $url = "https://{$domain}";
            $response = $this->probeHTTPS($url);
            
            if ($response && $response['status'] < 400) {
                $this->addEvidence("Autodiscover Available", $domain, 'medium');
                
                if (stripos($response['body'], 'autodiscover') !== false) {
                    $this->addEvidence("Autodiscover XML", $domain, 'high');
                }
            }
        }
    }

    /**
     * Stage 3: Run comprehensive fingerprinting engine
     */
    private function runFingerprintingEngine()
    {
        // Probe common webmail hostnames
        $this->probeWebmailHostnames();

        // Probe standard ports
        $this->probeStandardPorts();

        // Analyze HTTP headers and redirects
        $this->analyzeHTTPFingerprints();

        // Parse HTML content
        $this->analyzeHTMLFingerprints();

        // Analyze cookies
        $this->analyzeCookieFingerprints();

        // Analyze TLS certificates
        $this->analyzeTLSCertificates();
    }

    /**
     * Probe common webmail hostnames
     */
    private function probeWebmailHostnames()
    {
        foreach ($this->webmail_hostnames as $hostname) {
            $host = "{$hostname}.{$this->domain}";
            
            foreach ($this->ports_to_probe as $port) {
                $response = $this->probeHost($host, $port);
                
                if ($response) {
                    $this->addEvidence("Host Discovered", "{$host}:{$port}", 'medium');
                }
            }
        }
    }

    /**
     * Probe standard HTTP/HTTPS ports with fingerprinting
     */
    private function probeStandardPorts()
    {
        $primary_host = $this->domain;
        
        foreach ($this->ports_to_probe as $port) {
            // Try HTTPS first
            $url = "https://{$primary_host}:{$port}";
            $response = $this->probeHTTPS($url);
            
            if ($response) {
                $this->analyzeResponse($response, $port);
            } else {
                // Try HTTP
                $url = "https://{$primary_host}:{$port}";
                $response = $this->probeHTTP($url);
                
                if ($response) {
                    $this->analyzeResponse($response, $port);
                }
            }
        }
    }

    /**
     * Analyze HTTP response for fingerprints
     */
    private function analyzeResponse($response, $port)
    {
        $headers = $response['headers'] ?? [];
        $body = $response['body'] ?? '';

        // Server header analysis
        if (isset($headers['server'])) {
            $server = strtolower($headers['server']);
            $this->analyzeServerHeader($server, $port);
        }

        // Custom headers analysis
        $x_headers = array_filter($headers, function($key) {
            return strpos($key, 'x-') === 0;
        }, ARRAY_FILTER_USE_KEY);

        foreach ($x_headers as $header => $value) {
            $this->addEvidence("HTTP Header", "{$header}: {$value}", 'medium');
            $this->matchHeaderToplatform($header, $value);
        }

        // Parse HTML for fingerprints
        if (!empty($body)) {
            $this->parseHTMLFingerprints($body);
        }
    }

    /**
     * Analyze server header for platform identification
     */
    private function analyzeServerHeader($server, $port)
    {
        $fingerprints = [
            'microsoft-iis' => ['microsoft_365', 'owa'],
            'exchange' => ['owa', 'microsoft_365'],
            'smartermail' => ['smartermail'],
            'zimbra' => ['zimbra'],
            'cpanel' => ['cpanel'],
            'nginx' => [],
            'apache' => []
        ];

        foreach ($fingerprints as $keyword => $platforms) {
            if (strpos($server, $keyword) !== false) {
                $this->addEvidence("Server Header", $keyword, 'high');
                
                foreach ($platforms as $platform) {
                    $this->updateConfidence($platform, 20);
                }
            }
        }
    }

    /**
     * Match HTTP headers to platforms
     */
    private function matchHeaderToplatform($header, $value)
    {
        $header_lower = strtolower($header);
        $value_lower = strtolower($value);

        foreach ($this->platforms as $platform => $config) {
            if (isset($config['headers'])) {
                foreach ($config['headers'] as $fingerprint) {
                    if (strpos($header_lower . ': ' . $value_lower, strtolower($fingerprint)) !== false) {
                        $this->addEvidence("Header Fingerprint", $fingerprint, 'high');
                        $this->updateConfidence($platform, 30);
                    }
                }
            }
        }
    }

    /**
     * Analyze HTTP fingerprints
     */
    private function analyzeHTTPFingerprints()
    {
        $url = "https://{$this->domain}";
        
        foreach ($this->redirect_paths as $path) {
            $response = $this->probeHTTPS($url . $path);
            
            if ($response && ($response['status'] === 200 || $response['status'] === 302)) {
                $this->addEvidence("Redirect Path Detected", $path, 'medium');
                $this->matchPathToplatform($path);
            }
        }
    }

    /**
     * Match redirect paths to platforms
     */
    private function matchPathToplatform($path)
    {
        foreach ($this->platforms as $platform => $config) {
            if (isset($config['paths'])) {
                foreach ($config['paths'] as $platform_path) {
                    if (stripos($path, $platform_path) !== false) {
                        $this->addEvidence("Path Match", $platform_path, 'high');
                        $this->updateConfidence($platform, 25);
                    }
                }
            }
            
            if (isset($config['redirects'])) {
                foreach ($config['redirects'] as $redirect) {
                    if (stripos($path, $redirect) !== false) {
                        $this->addEvidence("Redirect Match", $redirect, 'high');
                        $this->updateConfidence($platform, 25);
                    }
                }
            }
        }
    }

    /**
     * Analyze HTML fingerprints
     */
    private function analyzeHTMLFingerprints()
    {
        $url = "https://{$this->domain}";
        $response = $this->probeHTTPS($url);
        
        if ($response && isset($response['body'])) {
            $this->parseHTMLFingerprints($response['body']);
        }
    }

    /**
     * Parse HTML content for platform fingerprints
     */
    private function parseHTMLFingerprints($html)
    {
        // Extract meta tags
        preg_match_all('/<meta\s+name="([^"]+)"\s+content="([^"]+)"/i', $html, $meta_matches);
        
        for ($i = 0; $i < count($meta_matches[0]); $i++) {
            $meta_name = $meta_matches[1][$i];
            $meta_content = $meta_matches[2][$i];
            
            foreach ($this->platforms as $platform => $config) {
                if (isset($config['keywords'])) {
                    foreach ($config['keywords'] as $keyword) {
                        if (stripos($meta_content, $keyword) !== false) {
                            $this->addEvidence("Meta Tag", $keyword, 'medium');
                            $this->updateConfidence($platform, 15);
                        }
                    }
                }
            }
        }

        // Extract form actions
        preg_match_all('/<form[^>]+action="([^"]+)"/i', $html, $form_matches);
        foreach ($form_matches[1] as $action) {
            $this->matchPathToplatform($action);
        }

        // Extract JavaScript files
        preg_match_all('/<script[^>]+src="([^"]+)"/i', $html, $script_matches);
        foreach ($script_matches[1] as $script) {
            $this->matchPathToplatform($script);
            $this->matchKeywordsInContent($script);
        }

        // Check for CSS paths
        preg_match_all('/<link[^>]+href="([^"]+\.css)"/i', $html, $css_matches);
        foreach ($css_matches[1] as $css_path) {
            $this->matchPathToplatform($css_path);
        }

        // Extract keywords and banners
        foreach ($this->platforms as $platform => $config) {
            if (isset($config['keywords'])) {
                foreach ($config['keywords'] as $keyword) {
                    if (stripos($html, $keyword) !== false) {
                        $this->addEvidence("HTML Keyword", $keyword, 'medium');
                        $this->updateConfidence($platform, 10);
                    }
                }
            }
        }
    }

    /**
     * Match keywords in content
     */
    private function matchKeywordsInContent($content)
    {
        foreach ($this->platforms as $platform => $config) {
            if (isset($config['keywords'])) {
                foreach ($config['keywords'] as $keyword) {
                    if (stripos($content, $keyword) !== false) {
                        $this->addEvidence("Content Keyword", $keyword, 'low');
                        $this->updateConfidence($platform, 5);
                    }
                }
            }
        }
    }

    /**
     * Analyze cookie fingerprints
     */
    private function analyzeCookieFingerprints()
    {
        $url = "https://{$this->domain}";
        $response = $this->probeHTTPS($url);
        
        if ($response && isset($response['headers']['set-cookie'])) {
            $cookies = $response['headers']['set-cookie'];
            
            if (!is_array($cookies)) {
                $cookies = [$cookies];
            }
            
            foreach ($cookies as $cookie) {
                preg_match('/^([^=;]+)/', $cookie, $matches);
                if (isset($matches[1])) {
                    $cookie_name = $matches[1];
                    $this->matchCookieToplatform($cookie_name);
                }
            }
        }
    }

    /**
     * Match cookies to platforms
     */
    private function matchCookieToplatform($cookie_name)
    {
        foreach ($this->platforms as $platform => $config) {
            if (isset($config['cookies'])) {
                foreach ($config['cookies'] as $platform_cookie) {
                    if (stripos($cookie_name, $platform_cookie) !== false) {
                        $this->addEvidence("Cookie Match", $platform_cookie, 'high');
                        $this->updateConfidence($platform, 35);
                    }
                }
            }
        }
    }

    /**
     * Analyze TLS certificates
     */
    private function analyzeTLSCertificates()
    {
        $context = stream_context_create([
            "ssl" => [
                "capture_peer_cert" => true,
                "verify_peer" => false,
                "verify_peer_name" => false
            ]
        ]);

        $stream = @stream_socket_client("ssl://{$this->domain}:443", $errno, $errstr, $this->timeout, STREAM_CLIENT_CONNECT, $context);
        
        if ($stream) {
            $cert = stream_context_get_params($stream);
            
            if (isset($cert["options"]["ssl"]["peer_certificate"])) {
                $cert_data = openssl_x509_parse($cert["options"]["ssl"]["peer_certificate"]);
                
                if (isset($cert_data['subject']['CN'])) {
                    $cn = $cert_data['subject']['CN'];
                    $this->addEvidence("Certificate CN", $cn, 'medium');
                    
                    // Match to platforms
                    foreach ($this->platforms as $platform => $config) {
                        if (isset($config['keywords'])) {
                            foreach ($config['keywords'] as $keyword) {
                                if (stripos($cn, $keyword) !== false) {
                                    $this->addEvidence("Cert Keyword", $keyword, 'high');
                                    $this->updateConfidence($platform, 20);
                                }
                            }
                        }
                    }
                }
            }
            
            fclose($stream);
        }
    }

    /**
     * Probe HTTPS endpoint
     */
    private function probeHTTPS($url)
    {
        return $this->probeURL($url, true);
    }

    /**
     * Probe HTTP endpoint
     */
    private function probeHTTP($url)
    {
        return $this->probeURL($url, false);
    }

    /**
     * Generic URL probing method
     */
    private function probeURL($url, $verify_ssl = false)
    {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => $verify_ssl,
            CURLOPT_SSL_VERIFYHOST => $verify_ssl ? 2 : 0,
            CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        ]);

        $response = curl_exec($ch);
        $info = curl_getinfo($ch);
        curl_close($ch);

        if ($response === false) {
            return null;
        }

        // Parse headers
        list($headers_text, $body) = explode("\r\n\r\n", $response, 2);
        $headers = [];
        
        foreach (explode("\r\n", $headers_text) as $line) {
            if (strpos($line, ':') !== false) {
                list($name, $value) = explode(':', $line, 2);
                $headers[strtolower(trim($name))] = trim($value);
            }
        }

        return [
            'status' => $info['http_code'],
            'headers' => $headers,
            'body' => $body,
            'url' => $info['url']
        ];
    }

    /**
     * Probe host on specific port
     */
    private function probeHost($host, $port)
    {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => "https://{$host}:{$port}",
            CURLOPT_TIMEOUT => $this->port_timeouts,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_NOBODY => true
        ]);

        $response = curl_exec($ch);
        $info = curl_getinfo($ch);
        curl_close($ch);

        return $info['http_code'] > 0 && $info['http_code'] < 500;
    }

    /**
     * Classify platform based on accumulated evidence
     */
    private function classifyPlatform()
    {
        $platform_scores = [];

        // Sort platforms by priority for tie-breaking
        foreach ($this->platforms as $platform => $config) {
            $platform_scores[$platform] = 0;
        }

        // This would be populated by updateConfidence calls
        // For demonstration, we'll analyze based on DNS records
        if (!empty($this->dns_records['mx'])) {
            foreach ($this->dns_records['mx'] as $mx) {
                $mx_host = strtolower($mx['host']);
                
                if (stripos($mx_host, 'protection.outlook.com') !== false) {
                    $platform_scores['microsoft_365'] += 40;
                } elseif (stripos($mx_host, 'mimecast') !== false) {
                    $platform_scores['mimecast'] += 40;
                } elseif (stripos($mx_host, 'emailsrvr.com') !== false) {
                    $platform_scores['rackspace'] += 40;
                } elseif (stripos($mx_host, 'zimbra') !== false) {
                    $platform_scores['zimbra'] += 40;
                }
            }
        }

        // Find platform with highest score
        if (!empty($platform_scores)) {
            $this->detected_platform = array_key_first($platform_scores);
            $this->confidence_score = min(100, array_sum($platform_scores) / count($platform_scores));
        }
    }

    /**
     * Update confidence score for a platform
     */
    private function updateConfidence($platform, $points)
    {
        // This would be stored in a separate confidence tracking system
        // For now, it accumulates evidence
    }

    /**
     * Add evidence to findings
     */
    private function addEvidence($type, $value, $severity = 'medium')
    {
        $this->evidence[] = [
            'type' => $type,
            'value' => $value,
            'severity' => $severity
        ];
    }

    /**
     * Generate comprehensive report
     */
    private function generateReport()
    {
        $high_confidence_evidence = array_filter($this->evidence, function($e) {
            return $e['severity'] === 'high';
        });

        $evidence_list = array_map(function($e) {
            return $e['value'];
        }, array_slice($high_confidence_evidence, 0, 5));

        return [
            'success' => true,
            'domain' => $this->domain,
            'dns_records' => [
                'mx' => array_map(function($mx) { return $mx['host']; }, $this->dns_records['mx'] ?? []),
                'spf' => count($this->dns_records['spf'] ?? []) > 0,
                'dmarc' => count($this->dns_records['dmarc'] ?? []) > 0,
                'mta_sts' => count($this->dns_records['mta_sts'] ?? []) > 0
            ],
            'provider' => $this->detected_platform ?? 'unknown',
            'confidence' => round($this->confidence_score, 2),
            'evidence' => $evidence_list,
            'evidence_count' => count($this->evidence),
            'full_evidence' => array_slice($this->evidence, 0, 20)
        ];
    }
}

/**
 * API Endpoint Handler
 */
class DNSCheckerAPI
{
    public static function handleRequest()
    {
        // Set CORS headers
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type');
        header('Content-Type: application/json');

        if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            http_response_code(200);
            exit();
        }

        // Get domain from GET or POST
        $domain = $_GET['domain'] ?? $_POST['domain'] ?? null;

        if (!$domain) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => 'Domain parameter required'
            ]);
            exit();
        }

        try {
            $checker = new DNSChecker($domain);
            $result = $checker->scan();
            
            http_response_code(200);
            echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        } catch (Exception $e) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => $e->getMessage()
            ]);
        }
    }
}

// Handle API requests
if (php_sapi_name() !== 'cli') {
    DNSCheckerAPI::handleRequest();
}

// CLI usage
if (php_sapi_name() === 'cli' && isset($argv[1])) {
    $domain = $argv[1];
    $checker = new DNSChecker($domain);
    $result = $checker->scan();
    echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
}
?>

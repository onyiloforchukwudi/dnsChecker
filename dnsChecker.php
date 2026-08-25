<?php

/**
 * DNS Checker & Webmail Client Discovery API
 * Advanced Heuristic-Based Detection Engine
 * 
 * Uses multi-layered approach:
 * 1. MX Record Analysis (High Priority)
 * 2. HTTP Redirect Analysis (Very High Priority)
 * 3. Favicon Hash Matching
 * 4. TLS Certificate Inspection
 * 5. HTML Content Scoring
 * 6. Cookie Analysis
 * 7. Server Header Analysis
 * 
 * @author DNS Checker API
 * @version 2.0.0
 */

class DNSChecker
{
    private $domain;
    private $timeout = 5;
    private $port_timeouts = 3;
    private $scores = [];
    private $evidence = [];
    private $dns_records = [];
    private $detected_provider = null;
    private $confidence = 0;

    // Provider Detection Patterns
    private $provider_signatures = [
        'roundcube' => [
            'html_indicators' => [
                '_task=login' => 5,
                '_task=mail' => 3,
                '_action=login' => 4,
                'roundcube_sessid' => 10,
                'rcmail' => 8,
                'skins/elastic' => 6,
                'skins/larry' => 6,
                'skins/classic' => 6,
                'program/js' => 4,
                'roundcube webmail' => 7,
                '/program/js/app.js' => 8,
                'zm-web-client' => -10  // Negative score if Zimbra
            ],
            'urls' => ['/roundcube/', '/roundcube/index.php', '/webmail/', '/webmail/index.php'],
            'redirect_paths' => ['/roundcube/', '/webmail/'],
            'favicon_hashes' => ['e7ae26c4e7c9be0b8c8c8e8c'], // Example hashes
            'mx_patterns' => [],
            'min_score' => 10
        ],
        'zimbra' => [
            'html_indicators' => [
                'zimbra' => 8,
                'zm-web-client' => 10,
                '/service/soap' => 8,
                '/service/preauth' => 8,
                '/modern/' => 7,
                'zextras' => 9,
                'carbonio' => 9,
                'ZmSettings' => 10,
                'ZmMsg' => 10,
                'loginOp=login' => 8,
                'ZM_AUTH_TOKEN' => 10,
                'ZM_TEST' => 10
            ],
            'urls' => ['/zimbra/', '/modern/', '/h/', '/service/extension', '/service/soap'],
            'redirect_paths' => ['/zimbra/', '/modern/', '/h/'],
            'favicon_hashes' => ['f3a7c2d8e4b1a9c5'], // Example hashes
            'mx_patterns' => ['zimbra', 'synacor'],
            'min_score' => 10
        ],
        'cpanel' => [
            'html_indicators' => [
                'cpanel' => 6,
                'cpsession' => 10,
                'cpaneld' => 8,
                'cpsrvd' => 8,
                '/webmail' => 5,
                'cpanel web' => 7,
                'roundcube' => -5  // Negative if Roundcube detected
            ],
            'urls' => ['/webmail', '/webmail/index.php'],
            'redirect_paths' => ['/webmail'],
            'ports' => [2095, 2096],
            'headers' => ['cpaneld', 'cpsrvd'],
            'cookies' => ['cpsession'],
            'min_score' => 8
        ],
        'horde' => [
            'html_indicators' => [
                'horde' => 6,
                'imp' => 6,
                'imp webmail' => 8,
                '/horde/' => 6,
                '/imp/' => 6,
                'logintask' => 8
            ],
            'urls' => ['/horde/', '/horde/index.php', '/imp/'],
            'redirect_paths' => ['/horde/', '/imp/'],
            'min_score' => 8
        ],
        'owa' => [
            'html_indicators' => [
                'OWA-CANARY' => 10,
                'X-OWA-CANARY' => 10,
                'X-OWA-Version' => 10,
                '/owa/' => 9,
                '/ecp/' => 9,
                'microsoft exchange' => 8,
                'outlook web app' => 8,
                'X-FEServer' => 10
            ],
            'urls' => ['/owa/', '/ecp/', '/owa/auth.owa'],
            'redirect_paths' => ['/owa/', '/ecp/'],
            'mx_patterns' => ['protection.outlook.com'],
            'min_score' => 12
        ],
        'microsoft_365' => [
            'mx_patterns' => ['protection.outlook.com', 'outlook.com', 'outlook-com.olc.protection.outlook.com'],
            'html_indicators' => [
                'microsoft 365' => 8,
                'outlook.office365.com' => 9
            ],
            'autodiscover' => ['autodiscover.outlook.com'],
            'min_score' => 15
        ],
        'protonmail' => [
            'mx_patterns' => ['mail.protonmail.ch', 'mailsec.protonmail.ch'],
            'html_indicators' => [
                'protonmail' => 8,
                'protonimap' => 9
            ],
            'min_score' => 10
        ],
        'zoho' => [
            'mx_patterns' => ['smtpin.zoho.com', 'smtpin2.zoho.com', 'smtpin3.zoho.com'],
            'html_indicators' => [
                'zoho' => 6,
                'mail.zoho.com' => 8
            ],
            'min_score' => 8
        ],
        'gmail' => [
            'mx_patterns' => ['gmail-smtp-in.l.google.com', 'aspmx.l.google.com'],
            'min_score' => 15
        ],
        'yahoo' => [
            'mx_patterns' => ['mta5.am0.yahoodns.net', 'mta6.am0.yahoodns.net'],
            'min_score' => 15
        ]
    ];

    public function __construct($domain)
    {
        $this->domain = trim(strtolower($domain));
        
        // Extract domain from email if needed
        if (strpos($this->domain, '@') !== false) {
            $parts = explode('@', $this->domain);
            $this->domain = end($parts);
        }

        if (filter_var($this->domain, FILTER_VALIDATE_DOMAIN) === false) {
            throw new Exception("Invalid domain: {$this->domain}");
        }

        // Initialize scores for all providers
        foreach ($this->provider_signatures as $provider => $config) {
            $this->scores[$provider] = 0;
        }
    }

    /**
     * Execute comprehensive detection scan
     */
    public function scan()
    {
        try {
            // Stage 1: MX Record Analysis (Highest Priority)
            $this->performDNSLookups();

            // Stage 2: HTTP Redirect Detection (Very High Priority)
            $this->detectHTTPRedirects();

            // Stage 3: Favicon Hash Matching
            $this->analyzeFaviconHashes();

            // Stage 4: TLS Certificate Analysis
            $this->analyzeTLSCertificates();

            // Stage 5: Comprehensive HTML Content Analysis
            $this->analyzeHTMLContent();

            // Stage 6: Cookie & Header Analysis
            $this->analyzeCookiesAndHeaders();

            // Stage 7: Port Scanning for cPanel/Specific Services
            $this->probeSpecificPorts();

            // Stage 8: Determine Best Match
            $this->determineBestMatch();

            return $this->generateReport();
        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    /**
     * Stage 1: MX Record Analysis
     */
    private function performDNSLookups()
    {
        $mx_records = dns_get_mx($this->domain);
        
        if (!$mx_records) {
            return;
        }

        foreach ($mx_records as $mx) {
            $host = strtolower($mx['host']);
            $this->addEvidence("MX Record", $host, 'high');

            // Score all providers based on MX patterns
            foreach ($this->provider_signatures as $provider => $config) {
                if (!isset($config['mx_patterns'])) {
                    continue;
                }

                foreach ($config['mx_patterns'] as $pattern) {
                    if (stripos($host, $pattern) !== false) {
                        $points = 15; // High confidence for MX match
                        $this->scores[$provider] += $points;
                        $this->addEvidence("MX Match", "$provider: $pattern", 'high');
                    }
                }
            }
        }

        $this->dns_records['mx'] = $mx_records;
    }

    /**
     * Stage 2: HTTP Redirect Detection (Very High Priority)
     */
    private function detectHTTPRedirects()
    {
        $base_url = "http://{$this->domain}";

        foreach ($this->provider_signatures as $provider => $config) {
            if (!isset($config['redirect_paths'])) {
                continue;
            }

            foreach ($config['redirect_paths'] as $path) {
                $response = $this->probeURL($base_url . $path);

                if (!$response) {
                    continue;
                }

                // Check for 301/302 redirects (strong signal)
                if (in_array($response['status'], [301, 302, 303, 307])) {
                    $location = $response['headers']['location'] ?? '';
                    
                    // If it redirects to itself or stays on path, it's probably the app
                    if (stripos($location, $path) !== false || empty($location)) {
                        $this->scores[$provider] += 20; // Very high confidence
                        $this->addEvidence("HTTP Redirect", "$provider: $path -> $location", 'high');
                    }
                }

                // 200 response at specific path is also good
                if ($response['status'] === 200) {
                    $this->scores[$provider] += 12;
                    $this->addEvidence("HTTP 200", "$provider: $path accessible", 'medium');
                }
            }
        }
    }

    /**
     * Stage 3: Favicon Hash Analysis
     */
    private function analyzeFaviconHashes()
    {
        $favicon_url = "http://{$this->domain}/favicon.ico";
        $favicon_data = @file_get_contents($favicon_url);

        if ($favicon_data === false) {
            return;
        }

        $favicon_hash = md5($favicon_data);
        $this->addEvidence("Favicon", "MD5: $favicon_hash", 'low');

        // Compare against known hashes (you'd expand this with real hashes)
        foreach ($this->provider_signatures as $provider => $config) {
            if (!isset($config['favicon_hashes'])) {
                continue;
            }

            if (in_array($favicon_hash, $config['favicon_hashes'])) {
                $this->scores[$provider] += 8;
                $this->addEvidence("Favicon Match", $provider, 'medium');
            }
        }
    }

    /**
     * Stage 4: TLS Certificate Analysis
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

        if (!$stream) {
            return;
        }

        $cert = stream_context_get_params($stream);

        if (isset($cert["options"]["ssl"]["peer_certificate"])) {
            $cert_data = openssl_x509_parse($cert["options"]["ssl"]["peer_certificate"]);

            if (isset($cert_data['subject']['O'])) {
                $organization = strtolower($cert_data['subject']['O']);
                $this->addEvidence("Certificate Org", $organization, 'medium');

                if (stripos($organization, 'zimbra') !== false || stripos($organization, 'synacor') !== false) {
                    $this->scores['zimbra'] += 12;
                    $this->addEvidence("Cert Analysis", "Zimbra organization detected", 'high');
                }

                if (stripos($organization, 'cpanel') !== false) {
                    $this->scores['cpanel'] += 12;
                    $this->addEvidence("Cert Analysis", "cPanel organization detected", 'high');
                }
            }

            if (isset($cert_data['subject']['CN'])) {
                $cn = strtolower($cert_data['subject']['CN']);
                $this->addEvidence("Certificate CN", $cn, 'low');
            }
        }

        fclose($stream);
    }

    /**
     * Stage 5: HTML Content Analysis with Scoring
     */
    private function analyzeHTMLContent()
    {
        $html = $this->fetchHTML("http://{$this->domain}");

        if (!$html) {
            return;
        }

        $html_lower = strtolower($html);

        foreach ($this->provider_signatures as $provider => $config) {
            if (!isset($config['html_indicators'])) {
                continue;
            }

            foreach ($config['html_indicators'] as $indicator => $points) {
                if (stripos($html_lower, strtolower($indicator)) !== false) {
                    $this->scores[$provider] += $points;
                    $this->addEvidence("HTML Indicator", "$provider: $indicator (+$points)", 'medium');
                }
            }
        }

        // Parse specific high-value patterns
        $this->parseAdvancedPatterns($html);
    }

    /**
     * Parse advanced patterns for high accuracy
     */
    private function parseAdvancedPatterns($html)
    {
        $html_lower = strtolower($html);

        // Roundcube-specific patterns
        preg_match_all('/name=["\']_task["\']\s+value=["\']([^"\']+)["\']/', $html, $matches);
        if (!empty($matches[1])) {
            foreach ($matches[1] as $task) {
                if (in_array($task, ['login', 'mail', 'logout'])) {
                    $this->scores['roundcube'] += 8;
                    $this->addEvidence("Roundcube Pattern", "_task=$task detected", 'high');
                }
            }
        }

        // Zimbra pattern: Check for specific JS variables
        if (preg_match('/ZmSettings|ZmMsg|ZmAction/', $html)) {
            $this->scores['zimbra'] += 10;
            $this->addEvidence("Zimbra Pattern", "Zm* JavaScript variables detected", 'high');
        }

        // cPanel pattern: Look for cPanel WebMail interface
        if (preg_match('/https?:\/\/[^\/]*:2096|https?:\/\/[^\/]*:2095/', $html)) {
            $this->scores['cpanel'] += 12;
            $this->addEvidence("cPanel Pattern", "cPanel ports (2095/2096) detected in HTML", 'high');
        }

        // Check for login forms with specific actions
        preg_match_all('/<form[^>]+action=["\']([^"\']+)["\']/', $html, $form_matches);
        if (!empty($form_matches[1])) {
            foreach ($form_matches[1] as $action) {
                $action_lower = strtolower($action);

                if (strpos($action_lower, 'roundcube') !== false) {
                    $this->scores['roundcube'] += 6;
                }
                if (strpos($action_lower, 'zimbra') !== false || strpos($action_lower, '/service/') !== false) {
                    $this->scores['zimbra'] += 6;
                }
            }
        }
    }

    /**
     * Stage 6: Cookie and Header Analysis
     */
    private function analyzeCookiesAndHeaders()
    {
        $response = $this->probeURL("http://{$this->domain}");

        if (!$response) {
            return;
        }

        $headers = $response['headers'] ?? [];

        // Check Set-Cookie headers
        foreach ($headers as $header_name => $header_value) {
            $header_value_lower = strtolower($header_value);

            if (stripos($header_name, 'set-cookie') !== false) {
                if (stripos($header_value, 'roundcube_sessid') !== false) {
                    $this->scores['roundcube'] += 15;
                    $this->addEvidence("Cookie", "roundcube_sessid detected", 'high');
                }
                if (stripos($header_value, 'ZM_AUTH_TOKEN') !== false || stripos($header_value, 'ZM_TEST') !== false) {
                    $this->scores['zimbra'] += 15;
                    $this->addEvidence("Cookie", "Zimbra session cookie detected", 'high');
                }
                if (stripos($header_value, 'cpsession') !== false) {
                    $this->scores['cpanel'] += 15;
                    $this->addEvidence("Cookie", "cpsession detected", 'high');
                }
                if (stripos($header_value, 'OWA-CANARY') !== false) {
                    $this->scores['owa'] += 15;
                    $this->addEvidence("Cookie", "OWA-CANARY detected", 'high');
                }
            }

            // Check Server header
            if (strtolower($header_name) === 'server') {
                if (stripos($header_value, 'zimbra') !== false) {
                    $this->scores['zimbra'] += 10;
                    $this->addEvidence("Server Header", "Zimbra detected", 'high');
                }
                if (stripos($header_value, 'cpanel') !== false || stripos($header_value, 'cpsrvd') !== false) {
                    $this->scores['cpanel'] += 10;
                    $this->addEvidence("Server Header", "cPanel detected", 'high');
                }
            }

            // Check X-* headers
            if (stripos($header_name, 'x-owa') !== false || stripos($header_name, 'x-feserver') !== false) {
                $this->scores['owa'] += 8;
                $this->addEvidence("Custom Header", "OWA header detected: $header_name", 'medium');
            }
        }
    }

    /**
     * Stage 7: Port Scanning for cPanel and Services
     */
    private function probeSpecificPorts()
    {
        // cPanel uses ports 2095 (non-SSL) and 2096 (SSL)
        foreach ([2095, 2096] as $port) {
            $response = $this->probeURL("https://{$this->domain}:{$port}", true);

            if ($response && $response['status'] < 400) {
                $this->scores['cpanel'] += 10;
                $this->addEvidence("Port Scan", "Port $port accessible (cPanel)", 'high');

                // Check response for cPanel markers
                if (isset($response['body'])) {
                    if (stripos($response['body'], 'cpanel') !== false) {
                        $this->scores['cpanel'] += 5;
                        $this->addEvidence("Port Content", "cPanel marker found on port $port", 'medium');
                    }
                }
            }
        }
    }

    /**
     * Determine best match based on scores
     */
    private function determineBestMatch()
    {
        arsort($this->scores);

        foreach ($this->scores as $provider => $score) {
            $min_score = $this->provider_signatures[$provider]['min_score'] ?? 10;

            if ($score >= $min_score) {
                $this->detected_provider = $provider;
                $this->confidence = min(100, ($score / 100) * 100);
                $this->addEvidence("Detection Result", "$provider detected with score $score", 'high');
                return;
            }
        }

        // If no provider meets minimum score, use highest scorer with reduced confidence
        $this->detected_provider = key($this->scores);
        $this->confidence = max(0, min(100, (current($this->scores) / 50) * 100));
        $this->addEvidence("Detection Result", "Fallback: {$this->detected_provider} with score " . current($this->scores), 'low');
    }

    /**
     * Fetch HTML content from URL
     */
    private function fetchHTML($url)
    {
        $response = $this->probeURL($url);
        return $response ? ($response['body'] ?? '') : null;
    }

    /**
     * Probe URL and return response
     */
    private function probeURL($url, $use_ssl = false)
    {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        ]);

        $response = curl_exec($ch);
        $info = curl_getinfo($ch);
        curl_close($ch);

        if ($response === false) {
            return null;
        }

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
            'body' => $body
        ];
    }

    /**
     * Add evidence for audit trail
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
     * Generate final report
     */
    private function generateReport()
    {
        $high_evidence = array_filter($this->evidence, function($e) {
            return $e['severity'] === 'high';
        });

        return [
            'success' => true,
            'domain' => $this->domain,
            'provider' => $this->detected_provider ?? 'unknown',
            'confidence' => round($this->confidence, 2),
            'scores' => $this->scores,
            'mx_records' => array_map(function($mx) { return $mx['host']; }, $this->dns_records['mx'] ?? []),
            'evidence' => array_map(function($e) { return $e['value']; }, array_slice($high_evidence, 0, 10)),
            'evidence_count' => count($this->evidence),
            'full_evidence' => array_slice($this->evidence, 0, 30)
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
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type');
        header('Content-Type: application/json');

        if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            http_response_code(200);
            exit();
        }

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

if (php_sapi_name() !== 'cli') {
    DNSCheckerAPI::handleRequest();
}

if (php_sapi_name() === 'cli' && isset($argv[1])) {
    $domain = $argv[1];
    $checker = new DNSChecker($domain);
    $result = $checker->scan();
    echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
}
?>

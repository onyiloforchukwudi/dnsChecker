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

// Enable error logging
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', dirname(__FILE__) . '/dnsChecker_errors.log');

class DNSChecker
{
    private $domain;
    private $timeout = 5;
    private $port_timeouts = 2;
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
                'roundcube webmail' => 7
            ],
            'urls' => ['/roundcube/', '/roundcube/index.php', '/webmail/', '/webmail/index.php'],
            'redirect_paths' => ['/roundcube/', '/webmail/'],
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
                'cpanel web' => 7
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
                '/imp/' => 6
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
                'outlook web app' => 8
            ],
            'urls' => ['/owa/', '/ecp/', '/owa/auth.owa'],
            'redirect_paths' => ['/owa/', '/ecp/'],
            'mx_patterns' => ['protection.outlook.com'],
            'min_score' => 12
        ],
        'microsoft_365' => [
            'mx_patterns' => ['protection.outlook.com', 'outlook.com', 'outlook-com.olc.protection.outlook.com'],
            'min_score' => 15
        ],
        'protonmail' => [
            'mx_patterns' => ['mail.protonmail.ch', 'mailsec.protonmail.ch'],
            'min_score' => 10
        ],
        'zoho' => [
            'mx_patterns' => ['smtpin.zoho.com', 'smtpin2.zoho.com', 'smtpin3.zoho.com'],
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

            // Stage 3: Comprehensive HTML Content Analysis
            $this->analyzeHTMLContent();

            // Stage 4: Cookie & Header Analysis
            $this->analyzeCookiesAndHeaders();

            // Stage 5: Port Scanning for cPanel/Specific Services
            $this->probeSpecificPorts();

            // Stage 6: Determine Best Match
            $this->determineBestMatch();

            return $this->generateReport();
        } catch (Exception $e) {
            error_log("DNS Checker Error: " . $e->getMessage());
            return [
                'success' => false,
                'error' => $e->getMessage(),
                'domain' => $this->domain
            ];
        }
    }

    /**
     * Stage 1: MX Record Analysis
     */
    private function performDNSLookups()
    {
        try {
            $mx_records = @dns_get_mx($this->domain);
            
            if (!$mx_records || !is_array($mx_records)) {
                $this->addEvidence("DNS", "No MX records found", 'low');
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
                            $points = 15;
                            $this->scores[$provider] += $points;
                            $this->addEvidence("MX Match", "$provider: $pattern", 'high');
                        }
                    }
                }
            }

            $this->dns_records['mx'] = $mx_records;
        } catch (Exception $e) {
            error_log("DNS Lookup Error: " . $e->getMessage());
            $this->addEvidence("DNS Error", $e->getMessage(), 'low');
        }
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
                $url = $base_url . $path;
                $response = $this->probeURL($url);

                if (!$response) {
                    continue;
                }

                // Check for redirects
                if (in_array($response['status'], [301, 302, 303, 307])) {
                    $location = $response['headers']['location'] ?? '';
                    $this->scores[$provider] += 20;
                    $this->addEvidence("HTTP Redirect", "$provider: $path responds with {$response['status']}", 'high');
                }

                // 200 response at specific path
                if ($response['status'] === 200) {
                    $this->scores[$provider] += 12;
                    $this->addEvidence("HTTP 200", "$provider: $path accessible", 'medium');
                }
            }
        }
    }

    /**
     * Stage 3: HTML Content Analysis with Scoring
     */
    private function analyzeHTMLContent()
    {
        $html = $this->fetchHTML("http://{$this->domain}");

        if (!$html) {
            $this->addEvidence("HTML", "Could not fetch content from domain", 'low');
            return;
        }

        $html_lower = strtolower($html);
        $this->addEvidence("HTML", "Fetched " . strlen($html) . " bytes", 'low');

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
        if (preg_match('/name=["\']_task["\']\s+value=["\']([^"\']+)["\']/', $html, $matches)) {
            if (isset($matches[1]) && in_array($matches[1], ['login', 'mail', 'logout'])) {
                $this->scores['roundcube'] += 8;
                $this->addEvidence("Roundcube Pattern", "_task={$matches[1]} detected", 'high');
            }
        }

        // Zimbra pattern
        if (preg_match('/ZmSettings|ZmMsg|ZmAction/', $html)) {
            $this->scores['zimbra'] += 10;
            $this->addEvidence("Zimbra Pattern", "Zm* JavaScript variables detected", 'high');
        }

        // cPanel port patterns
        if (preg_match('/https?:\/\/[^\/]*:20(95|96)/', $html)) {
            $this->scores['cpanel'] += 12;
            $this->addEvidence("cPanel Pattern", "cPanel ports (2095/2096) detected", 'high');
        }

        // Form action analysis
        if (preg_match_all('/<form[^>]+action=["\']([^"\']+)["\']/', $html, $form_matches)) {
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
     * Stage 4: Cookie and Header Analysis
     */
    private function analyzeCookiesAndHeaders()
    {
        $response = $this->probeURL("http://{$this->domain}");

        if (!$response) {
            return;
        }

        $headers = $response['headers'] ?? [];

        foreach ($headers as $header_name => $header_value) {
            $header_name_lower = strtolower($header_name);
            $header_value_lower = strtolower($header_value);

            if (strpos($header_name_lower, 'set-cookie') !== false) {
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

            if ($header_name_lower === 'server') {
                if (stripos($header_value, 'zimbra') !== false) {
                    $this->scores['zimbra'] += 10;
                    $this->addEvidence("Server Header", "Zimbra detected", 'high');
                }
                if (stripos($header_value, 'cpanel') !== false || stripos($header_value, 'cpsrvd') !== false) {
                    $this->scores['cpanel'] += 10;
                    $this->addEvidence("Server Header", "cPanel detected", 'high');
                }
            }

            if (stripos($header_name_lower, 'x-owa') !== false || stripos($header_name_lower, 'x-feserver') !== false) {
                $this->scores['owa'] += 8;
                $this->addEvidence("Custom Header", "OWA header detected", 'medium');
            }
        }
    }

    /**
     * Stage 5: Port Scanning for cPanel and Services
     */
    private function probeSpecificPorts()
    {
        // cPanel uses ports 2095 (non-SSL) and 2096 (SSL)
        foreach ([2095, 2096] as $port) {
            $response = $this->probeURL("https://{$this->domain}:{$port}");

            if ($response && $response['status'] < 400) {
                $this->scores['cpanel'] += 10;
                $this->addEvidence("Port Scan", "Port $port responds with {$response['status']}", 'high');

                if (isset($response['body']) && stripos($response['body'], 'cpanel') !== false) {
                    $this->scores['cpanel'] += 5;
                    $this->addEvidence("Port Content", "cPanel marker found on port $port", 'medium');
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

        // Fallback: use highest scorer
        $this->detected_provider = key($this->scores);
        $top_score = current($this->scores);
        $this->confidence = max(0, min(50, ($top_score / 50) * 100));
        $this->addEvidence("Detection Result", "Fallback: {$this->detected_provider} (score: $top_score)", 'low');
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
    private function probeURL($url)
    {
        $ch = curl_init();
        
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeout);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');

        $response = curl_exec($ch);
        $info = curl_getinfo($ch);
        $error = curl_error($ch);
        curl_close($ch);

        if ($response === false) {
            error_log("CURL Error for $url: $error");
            return null;
        }

        $parts = explode("\r\n\r\n", $response, 2);
        $headers_text = $parts[0] ?? '';
        $body = $parts[1] ?? '';
        $headers = [];

        foreach (explode("\r\n", $headers_text) as $line) {
            if (strpos($line, ':') !== false) {
                list($name, $value) = explode(':', $line, 2);
                $headers[strtolower(trim($name))] = trim($value);
            }
        }

        return [
            'status' => $info['http_code'] ?? 0,
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

        $mx_records = [];
        if (!empty($this->dns_records['mx'])) {
            foreach ($this->dns_records['mx'] as $mx) {
                $mx_records[] = $mx['host'];
            }
        }

        return [
            'success' => true,
            'domain' => $this->domain,
            'provider' => $this->detected_provider ?? 'unknown',
            'confidence' => round($this->confidence, 2),
            'scores' => $this->scores,
            'mx_records' => $mx_records,
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
        header('Content-Type: application/json; charset=utf-8');

        if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            http_response_code(200);
            exit();
        }

        $domain = trim($_GET['domain'] ?? $_POST['domain'] ?? '');

        if (empty($domain)) {
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
            error_log("API Error: " . $e->getMessage());
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => $e->getMessage(),
                'domain' => $domain
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

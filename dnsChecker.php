<?php

/**
 * DNS Checker & Webmail Client Discovery API
 * Advanced Heuristic-Based Detection Engine with MX Server Probing
 * 
 * Multi-stage detection to differentiate between:
 * - Zimbra
 * - cPanel/WHM Mail
 * - Roundcube (on any server)
 * 
 * @author DNS Checker API
 * @version 2.2.0
 */

error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', dirname(__FILE__) . '/dnsChecker_errors.log');

class DNSChecker
{
    private $domain;
    private $timeout = 3;
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
                'roundcube_sessid' => 10,
                'rcmail' => 8,
                'skins/elastic' => 6,
                'skins/larry' => 6,
                'program/js' => 4,
                'roundcube webmail' => 7,
                '/program/js/app.js' => 8,
                'index.php?_task=' => 6
            ],
            'webmail_paths' => ['/roundcube/', '/mail/', '/webmail/', '/rc/', '/mailbox/'],
            'server_banners' => ['roundcube', 'rcmail'],
            'cookies' => ['roundcube_sessid'],
            'min_score' => 10,
            'mx_probe_weight' => 30
        ],
        'zimbra' => [
            'html_indicators' => [
                'zimbra' => 8,
                'zm-web-client' => 10,
                '/service/soap' => 8,
                '/modern/' => 7,
                'zextras' => 9,
                'carbonio' => 9,
                'ZmSettings' => 10,
                'ZmMsg' => 10,
                'ZM_AUTH_TOKEN' => 10,
                'ZM_TEST' => 10,
                'zimbraVersion' => 9,
                '/service/preauth' => 9
            ],
            'webmail_paths' => ['/zimbra/', '/modern/', '/h/', '/service/extension', '/service/soap', '/mail/'],
            'server_banners' => ['zimbra', 'synacor'],
            'cookies' => ['ZM_AUTH_TOKEN', 'ZM_TEST'],
            'min_score' => 10,
            'mx_probe_weight' => 30
        ],
        'cpanel' => [
            'html_indicators' => [
                'cpanel' => 6,
                'cpsession' => 10,
                'cpaneld' => 8,
                '/webmail' => 5,
                'whm' => 8,
                'autodiscover.xml' => 7
            ],
            'webmail_paths' => ['/webmail/', '/webmail/index.php', '/mail/', '/horde/', '/roundcube/'],
            'server_banners' => ['cpanel', 'cpsrvd', 'webserver'],
            'cookies' => ['cpsession', 'horde_imp_key'],
            'ports' => [2095, 2096],
            'min_score' => 8,
            'mx_probe_weight' => 25
        ],
        'horde' => [
            'html_indicators' => [
                'horde' => 6,
                'imp webmail' => 8,
                '/horde/' => 6,
                '/imp/' => 6,
                'horde_imp_key' => 8
            ],
            'webmail_paths' => ['/horde/', '/imp/', '/mail/'],
            'server_banners' => ['horde', 'imp'],
            'cookies' => ['horde_imp_key'],
            'min_score' => 8,
            'mx_probe_weight' => 20
        ],
        'owa' => [
            'html_indicators' => [
                'OWA-CANARY' => 10,
                '/owa/' => 9,
                '/ecp/' => 9,
                'outlook web app' => 8
            ],
            'webmail_paths' => ['/owa/', '/ecp/', '/owa/auth.owa'],
            'server_banners' => ['exchange', 'microsoft-iis'],
            'cookies' => ['OWA-CANARY'],
            'mx_patterns' => ['protection.outlook.com'],
            'min_score' => 12,
            'mx_probe_weight' => 30
        ],
        'microsoft_365' => [
            'mx_patterns' => ['protection.outlook.com', 'outlook.com'],
            'min_score' => 15,
            'mx_probe_weight' => 40
        ],
        'protonmail' => [
            'mx_patterns' => ['mail.protonmail.ch', 'mailsec.protonmail.ch'],
            'min_score' => 10,
            'mx_probe_weight' => 40
        ],
        'zoho' => [
            'mx_patterns' => ['smtpin.zoho.com', 'smtpin2.zoho.com'],
            'min_score' => 8,
            'mx_probe_weight' => 35
        ],
        'gmail' => [
            'mx_patterns' => ['gmail-smtp-in.l.google.com', 'aspmx.l.google.com'],
            'min_score' => 15,
            'mx_probe_weight' => 40
        ],
        'yahoo' => [
            'mx_patterns' => ['mta5.am0.yahoodns.net', 'mta6.am0.yahoodns.net'],
            'min_score' => 15,
            'mx_probe_weight' => 40
        ]
    ];

    public function __construct($domain)
    {
        $this->domain = trim(strtolower($domain));
        
        if (strpos($this->domain, '@') !== false) {
            $parts = explode('@', $this->domain);
            $this->domain = end($parts);
        }

        if (filter_var($this->domain, FILTER_VALIDATE_DOMAIN) === false) {
            throw new Exception("Invalid domain: {$this->domain}");
        }

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
            // Stage 1: MX Record Analysis
            $this->performDNSLookups();

            // Stage 2: Probe MX Server(s) - KEY STAGE
            $this->probeMXServers();

            // Stage 3: HTTP Redirect Detection
            $this->detectHTTPRedirects();

            // Stage 4: HTML Content Analysis
            $this->analyzeHTMLContent();

            // Stage 5: Cookie and Header Analysis
            $this->analyzeCookiesAndHeaders();

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
            $mx_records = [];
            if (@dns_get_mx($this->domain, $mx_records)) {
                if (!empty($mx_records) && is_array($mx_records)) {
                    foreach ($mx_records as $host) {
                        $host = strtolower($host);
                        $this->addEvidence("MX Record", $host, 'high');
                        
                        // Score based on known MX providers
                        foreach ($this->provider_signatures as $provider => $config) {
                            if (!isset($config['mx_patterns'])) {
                                continue;
                            }
                            foreach ($config['mx_patterns'] as $pattern) {
                                if (stripos($host, $pattern) !== false) {
                                    $weight = $config['mx_probe_weight'] ?? 15;
                                    $this->scores[$provider] += $weight;
                                    $this->addEvidence("MX Match", "$provider: $pattern", 'high');
                                }
                            }
                        }
                    }
                    $this->dns_records['mx'] = $mx_records;
                }
            } else {
                $this->addEvidence("DNS", "No MX records found", 'low');
            }
        } catch (Exception $e) {
            error_log("DNS Lookup Error: " . $e->getMessage());
        }
    }

    /**
     * Stage 2: Probe MX Server - DIFFERENTIATE BETWEEN LOCAL PROVIDERS
     * This is crucial when multiple providers share same MX record
     */
    private function probeMXServers()
    {
        if (empty($this->dns_records['mx'])) {
            return;
        }

        // Get first MX host
        $mx_host = strtolower($this->dns_records['mx'][0]);
        $this->addEvidence("MX Host Probing", "Probing $mx_host", 'medium');

        // Resolve MX hostname to IP
        $ip = @gethostbyname($mx_host);
        if ($ip === $mx_host) {
            // Resolution failed, try alternative methods
            $ips = @dns_get_record($mx_host, DNS_A);
            if ($ips && is_array($ips)) {
                $ip = $ips[0]['ip'] ?? $mx_host;
            }
        }

        if ($ip === $mx_host) {
            $this->addEvidence("DNS Resolution", "Could not resolve $mx_host", 'low');
            return;
        }

        $this->addEvidence("MX IP", $ip, 'medium');

        // Probe various ports and paths on the MX server
        $this->probeMailServerPorts($mx_host, $ip);
    }

    /**
     * Probe MX server on various ports for platform identification
     */
    private function probeMailServerPorts($mx_host, $ip)
    {
        // SMTP Banner Detection (port 25, 587, 465)
        $smtp_ports = [25, 587, 465];
        foreach ($smtp_ports as $port) {
            $banner = $this->getSMTPBanner($mx_host, $port);
            if ($banner) {
                $this->analyzeMailServerBanner($banner);
            }
        }

        // HTTP/HTTPS Webmail Interfaces
        $webmail_ports = [80, 443, 8080, 8443, 2095, 2096];
        foreach ($webmail_ports as $port) {
            $protocol = in_array($port, [443, 2096, 8443]) ? 'https' : 'http';
            $url = "$protocol://$mx_host:$port";
            
            $this->probeWebmailInterface($url);
        }

        // Common webmail paths on the domain itself
        foreach ($this->provider_signatures as $provider => $config) {
            if (!isset($config['webmail_paths'])) {
                continue;
            }

            foreach ($config['webmail_paths'] as $path) {
                $url = "http://{$this->domain}$path";
                $response = $this->probeURL($url);
                
                if ($response && $response['status'] === 200) {
                    $this->analyzeWebmailResponse($response, $provider);
                }
            }
        }
    }

    /**
     * Get SMTP banner for server identification
     */
    private function getSMTPBanner($host, $port)
    {
        $timeout = 2;
        $sock = @fsockopen($host, $port, $errno, $errstr, $timeout);
        
        if (!$sock) {
            return null;
        }

        stream_set_timeout($sock, $timeout);
        $banner = @fgets($sock, 1024);
        @fclose($sock);

        return $banner ? trim($banner) : null;
    }

    /**
     * Analyze SMTP banner for platform indicators
     */
    private function analyzeMailServerBanner($banner)
    {
        $banner_lower = strtolower($banner);

        // Zimbra SMTP banner
        if (stripos($banner, 'zimbra') !== false || stripos($banner, 'synacor') !== false) {
            $this->scores['zimbra'] += 25;
            $this->addEvidence("SMTP Banner", "Zimbra detected: $banner", 'high');
        }

        // cPanel/Exim (common on cPanel)
        if (stripos($banner, 'exim') !== false) {
            $this->scores['cpanel'] += 15;
            $this->addEvidence("SMTP Banner", "Exim (cPanel): $banner", 'high');
        }

        // Postfix (common on Roundcube/standalone)
        if (stripos($banner, 'postfix') !== false) {
            $this->scores['roundcube'] += 10;
            $this->addEvidence("SMTP Banner", "Postfix: $banner", 'medium');
        }

        // Sendmail
        if (stripos($banner, 'sendmail') !== false) {
            $this->scores['roundcube'] += 8;
            $this->addEvidence("SMTP Banner", "Sendmail: $banner", 'medium');
        }
    }

    /**
     * Probe webmail interface
     */
    private function probeWebmailInterface($url)
    {
        $response = $this->probeURL($url);
        if (!$response || $response['status'] !== 200) {
            return;
        }

        $body_lower = strtolower($response['body'] ?? '');
        $headers = $response['headers'] ?? [];

        // Check server header
        if (isset($headers['server'])) {
            $server_lower = strtolower($headers['server']);
            if (stripos($server_lower, 'zimbra') !== false) {
                $this->scores['zimbra'] += 20;
                $this->addEvidence("Webmail Server", "Zimbra webmail found at $url", 'high');
            }
            if (stripos($server_lower, 'roundcube') !== false) {
                $this->scores['roundcube'] += 25;
                $this->addEvidence("Webmail Server", "Roundcube webmail found at $url", 'high');
            }
        }

        // Check body content
        if (stripos($body_lower, 'zimbraVersion') !== false) {
            $this->scores['zimbra'] += 30;
            $this->addEvidence("Webmail Content", "Zimbra version detected at $url", 'high');
        }
        if (stripos($body_lower, 'ZmSettings') !== false) {
            $this->scores['zimbra'] += 25;
            $this->addEvidence("Webmail Content", "Zimbra JS config found at $url", 'high');
        }
        if (stripos($body_lower, 'roundcube') !== false && stripos($body_lower, '_task=') !== false) {
            $this->scores['roundcube'] += 25;
            $this->addEvidence("Webmail Content", "Roundcube interface found at $url", 'high');
        }
        if (stripos($body_lower, 'cpanel') !== false) {
            $this->scores['cpanel'] += 15;
            $this->addEvidence("Webmail Content", "cPanel interface found at $url", 'medium');
        }
    }

    /**
     * Analyze webmail response
     */
    private function analyzeWebmailResponse($response, $provider)
    {
        $body_lower = strtolower($response['body'] ?? '');
        $headers = $response['headers'] ?? [];

        if (!isset($this->provider_signatures[$provider]['webmail_paths'])) {
            return;
        }

        // Check for provider-specific indicators
        if (isset($this->provider_signatures[$provider]['html_indicators'])) {
            foreach ($this->provider_signatures[$provider]['html_indicators'] as $indicator => $weight) {
                if (stripos($body_lower, strtolower($indicator)) !== false) {
                    $this->scores[$provider] += ($weight * 1.5); // Boost when found in webmail path
                    $this->addEvidence("Webmail Match", "$provider: $indicator", 'high');
                }
            }
        }
    }

    /**
     * Stage 3: HTTP Redirect Detection
     */
    private function detectHTTPRedirects()
    {
        $base_url = "http://{$this->domain}";

        foreach ($this->provider_signatures as $provider => $config) {
            if (!isset($config['webmail_paths'])) {
                continue;
            }

            foreach ($config['webmail_paths'] as $path) {
                $url = $base_url . $path;
                $response = $this->probeURL($url);

                if (!$response) {
                    continue;
                }

                if (in_array($response['status'], [301, 302, 303, 307])) {
                    $this->scores[$provider] += 20;
                    $this->addEvidence("HTTP Redirect", "$provider: $path", 'high');
                }

                if ($response['status'] === 200) {
                    $this->scores[$provider] += 12;
                    $this->addEvidence("HTTP 200", "$provider: $path", 'medium');
                }
            }
        }
    }

    /**
     * Stage 4: HTML Content Analysis
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
                    $this->addEvidence("HTML Indicator", "$provider: $indicator", 'medium');
                }
            }
        }

        $this->parseAdvancedPatterns($html);
    }

    /**
     * Parse advanced patterns
     */
    private function parseAdvancedPatterns($html)
    {
        // Roundcube form detection
        if (preg_match('/name=["\']_task["\']\s+value=["\']([^"\']+)["\']/', $html, $m)) {
            if (isset($m[1]) && in_array($m[1], ['login', 'mail'])) {
                $this->scores['roundcube'] += 10;
                $this->addEvidence("Roundcube Form", "_task={$m[1]}", 'high');
            }
        }

        // Zimbra JS variables
        if (preg_match('/ZmSettings|ZmMsg|ZmAction|zimbraVersion/', $html)) {
            $this->scores['zimbra'] += 15;
            $this->addEvidence("Zimbra JS", "Zm* variables", 'high');
        }

        // cPanel port detection
        if (preg_match('/https?:\/\/[^\/]*:20(95|96)/', $html)) {
            $this->scores['cpanel'] += 15;
            $this->addEvidence("cPanel Ports", "2095/2096", 'high');
        }
    }

    /**
     * Stage 5: Cookie and Header Analysis
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

            if (strpos($header_name_lower, 'set-cookie') !== false) {
                if (stripos($header_value, 'roundcube_sessid') !== false) {
                    $this->scores['roundcube'] += 20;
                    $this->addEvidence("Cookie", "roundcube_sessid", 'high');
                }
                if (stripos($header_value, 'ZM_AUTH_TOKEN') !== false) {
                    $this->scores['zimbra'] += 20;
                    $this->addEvidence("Cookie", "Zimbra session", 'high');
                }
                if (stripos($header_value, 'cpsession') !== false) {
                    $this->scores['cpanel'] += 20;
                    $this->addEvidence("Cookie", "cpsession", 'high');
                }
            }

            if ($header_name_lower === 'server') {
                if (stripos($header_value, 'zimbra') !== false) {
                    $this->scores['zimbra'] += 15;
                    $this->addEvidence("Server", "Zimbra", 'high');
                }
                if (stripos($header_value, 'exim') !== false || stripos($header_value, 'cpanel') !== false) {
                    $this->scores['cpanel'] += 15;
                    $this->addEvidence("Server", "cPanel/Exim", 'high');
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
                $this->addEvidence("Detection", "$provider (score: $score)", 'high');
                return;
            }
        }

        $this->detected_provider = key($this->scores);
        $top_score = current($this->scores);
        $this->confidence = max(0, min(40, ($top_score / 50) * 100));
        $this->addEvidence("Detection", "Fallback: {$this->detected_provider} (score: $top_score)", 'low');
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
     * Probe URL with timeout and error handling
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
        curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0');
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 2);

        $response = @curl_exec($ch);
        $info = curl_getinfo($ch);
        curl_close($ch);

        if ($response === false || empty($response)) {
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

        return [
            'success' => true,
            'domain' => $this->domain,
            'provider' => $this->detected_provider ?? 'unknown',
            'confidence' => round($this->confidence, 2),
            'scores' => $this->scores,
            'mx_records' => $this->dns_records['mx'] ?? [],
            'evidence' => array_map(function($e) { return $e['value']; }, array_slice($high_evidence, 0, 15)),
            'evidence_count' => count($this->evidence)
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
            echo json_encode(['success' => false, 'error' => 'Domain required']);
            exit();
        }

        try {
            $checker = new DNSChecker($domain);
            $result = $checker->scan();
            http_response_code(200);
            echo json_encode($result);
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
    $checker = new DNSChecker($argv[1]);
    echo json_encode($checker->scan());
}
?>

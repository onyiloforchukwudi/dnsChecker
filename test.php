<?php
/**
 * Quick Test Script for dnsChecker
 * Run: php test.php rockchem.com.pk
 * Or: php test.php (and it will use default test domain)
 */

require_once 'dnsChecker.php';

$domain = $argv[1] ?? 'rockchem.com.pk';

echo "\n" . str_repeat("=", 70) . "\n";
echo "DNS Checker - Email Hosting Detection\n";
echo str_repeat("=", 70) . "\n";
echo "Testing Domain: $domain\n";
echo str_repeat("-", 70) . "\n\n";

try {
    $checker = new DNSChecker($domain);
    $result = $checker->scan();
    
    echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    echo "\n\n" . str_repeat("=", 70) . "\n";
    
} catch (Exception $e) {
    echo "ERROR: " . $e->getMessage() . "\n";
    echo str_repeat("=", 70) . "\n";
}
?>

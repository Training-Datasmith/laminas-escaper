<?php

declare(strict_types=1);

/**
 * Example: Basic context-aware output escaping with laminas-escaper.
 *
 * This script demonstrates the five escaping contexts and why using
 * the correct escaper for each context matters for XSS prevention.
 *
 * Run standalone:
 *   php examples/basic_escaping.php
 */

require_once __DIR__ . '/../vendor/autoload.php';

use Laminas\Escaper\Escaper;

$escaper = new Escaper('utf-8');

$untrusted = '<script>alert("XSS & danger")</script>';

// 1. HTML body context — safe between tags
echo "HTML body: " . $escaper->escape_html($untrusted) . PHP_EOL;
// Output: &lt;script&gt;alert(&quot;XSS &amp; danger&quot;)&lt;/script&gt;

// 2. HTML attribute context — safe inside attribute values
$attr_value = '" onmouseover="alert(1)';
echo "HTML attr: <input value=\"" . $escaper->escape_html_attr($attr_value) . "\">" . PHP_EOL;
// Output: <input value="&#x22;&#x20;onmouseover&#x3D;&#x22;alert&#x28;1&#x29;">

// 3. JavaScript context — safe inside a JS string literal
$js_value = "'; alert('XSS'); //";
echo "JS string: var x = '" . $escaper->escape_js($js_value) . "';" . PHP_EOL;
// Output: var x = '\x27\x3B\x20alert\x28\x27XSS\x27\x29\x3B\x20\x2F\x2F';

// 4. URL context — safe as a query parameter value
$url_param = 'search term & more <stuff>';
echo "URL param: https://example.com/?q=" . $escaper->escape_url($url_param) . PHP_EOL;
// Output: https://example.com/?q=search%20term%20%26%20more%20%3Cstuff%3E

// 5. CSS context — safe inside a CSS property value
$css_value = 'red; background: url(evil)';
echo "CSS value: color: " . $escaper->escape_css($css_value) . ";" . PHP_EOL;
// Output: color: red\3B \20 background\3A \20 url\28 evil\29 ;

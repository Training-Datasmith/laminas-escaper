<?php

declare(strict_types=1);

/**
 * Example: Using laminas-escaper with a non-UTF-8 encoding.
 *
 * For legacy applications that operate in ISO-8859-1 (Latin-1),
 * the Escaper can be configured to accept and return strings in
 * that encoding while still applying safe UTF-8-based escaping
 * internally.
 *
 * Run standalone:
 *   php examples/custom_encoding.php
 */

require_once __DIR__ . '/../vendor/autoload.php';

use Laminas\Escaper\Escaper;

// Build an ISO-8859-1 string: "Café <script>"
$latin1_string = "Caf\xE9 <script>";

$escaper = new Escaper('iso-8859-1');

echo "Encoding: " . $escaper->get_encoding() . PHP_EOL;

// escape_html_attr converts to UTF-8 internally, escapes, then converts back
$escaped = $escaper->escape_html_attr($latin1_string);
echo "Escaped (ISO-8859-1): " . $escaped . PHP_EOL;
// The é (0xE9) is preserved as &#xE9; in the output

<?php

declare(strict_types=1);

namespace Laminas_Test\Escaper;

use Laminas\Escaper\Escaper;
use Laminas\Escaper\Exception\RuntimeException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;

/**
 * Security regression tests for Escaper — XSS prevention across all five contexts.
 *
 * These tests validate that the escaper correctly neutralises known XSS vectors
 * that have historically been used to bypass output escaping in each context.
 */
class Escaper_Security_Test extends TestCase
{
    private Escaper $escaper;

    protected function setUp(): void
    {
        $this->escaper = new Escaper('utf-8');
    }

    // -----------------------------------------------------------------------
    // HTML body context
    // -----------------------------------------------------------------------

    /**
     * @return array<string, array{0: string, 1: string}>
     */
    public static function html_xss_vectors_provider(): array
    {
        return [
            'script tag'              => ['<script>alert(1)</script>', '&lt;script&gt;alert(1)&lt;/script&gt;'],
            'double-quote break'      => ['"onload="alert(1)', '&quot;onload=&quot;alert(1)'],
            'ampersand entity bypass' => ['&lt;script&gt;', '&amp;lt;script&amp;gt;'],
            'null byte'               => ["\x00", "\x00"],  // null byte passes through (handled by browser)
            'angle brackets'          => ['<>', '&lt;&gt;'],
        ];
    }

    #[DataProvider('html_xss_vectors_provider')]
    #[Group('security')]
    #[Group('xss')]
    public function test_escape_html_neutralises_xss_vectors(string $input, string $expected): void
    {
        self::assertSame($expected, $this->escaper->escape_html($input));
    }

    // -----------------------------------------------------------------------
    // HTML attribute context
    // -----------------------------------------------------------------------

    /**
     * @return array<string, array{0: string}>
     */
    public static function html_attr_xss_vectors_provider(): array
    {
        return [
            'double-quote break'   => ['" onmouseover="alert(1)'],
            'single-quote break'   => ["' onfocus='alert(1)"],
            'backtick quote'       => ['` onload=`alert(1)`'],
            'space-encoded bypass' => [' style=color:red'],
            'null byte injection'  => ["\x00"],
            'angle bracket'        => ['<img src=x>'],
        ];
    }

    #[DataProvider('html_attr_xss_vectors_provider')]
    #[Group('security')]
    #[Group('xss')]
    public function test_escape_html_attr_output_differs_from_input_for_xss_vectors(string $input): void
    {
        $escaped = $this->escaper->escape_html_attr($input);
        // The escaped output must never contain the raw injection characters
        self::assertStringNotContainsString('"', $escaped, "Unescaped double-quote in attribute output");
        self::assertStringNotContainsString("'", $escaped, "Unescaped single-quote in attribute output");
        self::assertStringNotContainsString('<', $escaped, "Unescaped less-than in attribute output");
        self::assertStringNotContainsString('>', $escaped, "Unescaped greater-than in attribute output");
        self::assertStringNotContainsString(' ', $escaped, "Unescaped space in attribute output");
    }

    // -----------------------------------------------------------------------
    // JavaScript context
    // -----------------------------------------------------------------------

    /**
     * @return array<string, array{0: string}>
     */
    public static function js_xss_vectors_provider(): array
    {
        return [
            'script close tag'    => ['</script>'],
            'single quote break'  => ["'; alert(1); //"],
            'double quote break'  => ['"; alert(1); //'],
            'backslash bypass'    => ['\\'; alert(1);'],
            'unicode escape'      => ['\u003cscript\u003e'],
            'newline injection'   => ["\nalert(1)"],
        ];
    }

    #[DataProvider('js_xss_vectors_provider')]
    #[Group('security')]
    #[Group('xss')]
    public function test_escape_js_output_differs_from_input_for_xss_vectors(string $input): void
    {
        $escaped = $this->escaper->escape_js($input);
        // Dangerous characters must be encoded in the output
        self::assertStringNotContainsString("'", $escaped, "Unescaped single-quote in JS output");
        self::assertStringNotContainsString('"', $escaped, "Unescaped double-quote in JS output");
        self::assertStringNotContainsString('<', $escaped, "Unescaped less-than in JS output");
        self::assertStringNotContainsString('>', $escaped, "Unescaped greater-than in JS output");
        self::assertStringNotContainsString("\n", $escaped, "Unescaped newline in JS output");
    }

    // -----------------------------------------------------------------------
    // URL context
    // -----------------------------------------------------------------------

    #[Group('security')]
    #[Group('xss')]
    public function test_escape_url_encodes_characters_that_break_url_context(): void
    {
        $input   = 'javascript:alert(1)';
        $escaped = $this->escaper->escape_url($input);
        // The colon must be encoded — prevents javascript: protocol injection
        self::assertStringNotContainsString(':', $escaped);
        self::assertSame('javascript%3Aalert%281%29', $escaped);
    }

    #[Group('security')]
    #[Group('xss')]
    public function test_escape_url_encodes_angle_brackets(): void
    {
        $escaped = $this->escaper->escape_url('<script>');
        self::assertStringNotContainsString('<', $escaped);
        self::assertStringNotContainsString('>', $escaped);
    }

    // -----------------------------------------------------------------------
    // CSS context
    // -----------------------------------------------------------------------

    #[Group('security')]
    #[Group('xss')]
    public function test_escape_css_encodes_expression_injection(): void
    {
        // A CSS expression() attack vector
        $input   = 'expression(alert(1))';
        $escaped = $this->escaper->escape_css($input);
        self::assertStringNotContainsString('(', $escaped, "Unescaped paren in CSS output");
        self::assertStringNotContainsString(')', $escaped, "Unescaped paren in CSS output");
    }

    #[Group('security')]
    #[Group('xss')]
    public function test_escape_css_encodes_url_injection(): void
    {
        $input   = 'url(http://evil.com/x.js)';
        $escaped = $this->escaper->escape_css($input);
        self::assertStringNotContainsString('(', $escaped);
        self::assertStringNotContainsString(')', $escaped);
        self::assertStringNotContainsString(':', $escaped);
    }

    // -----------------------------------------------------------------------
    // Encoding integrity — escape functions must be idempotent-safe
    // (escaping twice should not "double-encode" in a way that loses context)
    // -----------------------------------------------------------------------

    #[Group('security')]
    public function test_escape_html_is_safe_with_already_escaped_input(): void
    {
        $once  = $this->escaper->escape_html('<b>Hello</b>');
        $twice = $this->escaper->escape_html($once);
        // Double-escaping changes the output — this is expected and correct:
        // double-escaping &amp; → &amp;amp; is a sign of misuse, not a bug.
        self::assertNotSame($once, $twice);
        // But the twice-escaped result must still contain no raw angle brackets
        self::assertStringNotContainsString('<', $twice);
        self::assertStringNotContainsString('>', $twice);
    }
}

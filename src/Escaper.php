<?php

declare (strict_types=1);
namespace Laminas\Escaper;

use function assert;
use function bin2hex;
use function ctype_digit;
use const ENT_QUOTES;
use const ENT_SUBSTITUTE;
use function hexdec;
use function htmlspecialchars;
use function in_array;
use function is_string;
use function mb_convert_encoding;
use function ord;
use function preg_match;
use function preg_replace_callback;
use function rawurlencode;
use function sprintf;
use function strlen;
use function strtolower;
use function strtoupper;
use function substr;
/**
 * Context specific methods for use in secure output escaping
 *
 * @final
 */
class Escaper implements Escaper_Interface
{
    /**
     * Entity Map mapping Unicode codepoints to any available named HTML entities.
     *
     * While HTML supports far more named entities, the lowest common denominator
     * has become HTML5's XML Serialisation which is restricted to the those named
     * entities that XML supports. Using HTML entities would result in this error:
     *     XML Parsing Error: undefined entity
     *
     * @var array<int, string>
     */
    protected static $html_named_entity_map = [
        34 => 'quot',
        // quotation mark
        38 => 'amp',
        // ampersand
        60 => 'lt',
        // less-than sign
        62 => 'gt',
    ];
    /**
     * Current encoding for escaping. If not UTF-8, we convert strings from this encoding
     * pre-escaping and back to this encoding post-escaping.
     *
     * @var non-empty-string
     */
    protected $encoding = 'utf-8';
    /**
     * Holds the value of the special flags passed as second parameter to
     * htmlspecialchars().
     */
    protected int $html_special_chars_flags;
    /**
     * Static Matcher which escapes characters for HTML Attribute contexts
     *
     * @var callable
     * @psalm-var callable(array<array-key, string>):string
     */
    protected $html_attr_matcher;
    /**
     * Static Matcher which escapes characters for Javascript contexts
     *
     * @var callable
     * @psalm-var callable(array<array-key, string>):string
     */
    protected $js_matcher;
    /**
     * Static Matcher which escapes characters for CSS Attribute contexts
     *
     * @var callable
     * @psalm-var callable(array<array-key, string>):string
     */
    protected $css_matcher;
    /**
     * List of all encoding supported by this class
     *
     * @var list<non-empty-string>
     */
    protected $supported_encodings = ['iso-8859-1', 'iso8859-1', 'iso-8859-5', 'iso8859-5', 'iso-8859-15', 'iso8859-15', 'utf-8', 'cp866', 'ibm866', '866', 'cp1251', 'windows-1251', 'win-1251', '1251', 'cp1252', 'windows-1252', '1252', 'koi8-r', 'koi8-ru', 'koi8r', 'big5', '950', 'gb2312', '936', 'big5-hkscs', 'shift_jis', 'sjis', 'sjis-win', 'cp932', '932', 'euc-jp', 'eucjp', 'eucjp-win', 'macroman'];
    /**
     * Constructor: Single parameter allows setting of global encoding for use by
     * the current object.
     *
     * @param non-empty-string|null $encoding
     * @throws Exception\InvalidArgumentException
     */
    public function __construct(?string $encoding = null)
    {
        if ($encoding !== null) {
            if ($encoding === '') {
                throw new Exception\InvalidArgumentException(static::class . ' constructor parameter does not allow a blank value');
            }
            $encoding = strtolower($encoding);
            if (!in_array($encoding, $this->supported_encodings)) {
                throw new Exception\InvalidArgumentException('Value of \'' . $encoding . '\' passed to ' . static::class . ' constructor parameter is invalid. Provide an encoding supported by htmlspecialchars()');
            }
            $this->encoding = $encoding;
        }
        // We take advantage of ENT_SUBSTITUTE flag to correctly deal with invalid UTF-8 sequences.
        $this->html_special_chars_flags = ENT_QUOTES | ENT_SUBSTITUTE;
        // set matcher callbacks
        $this->html_attr_matcher = $this->html_attr_matcher(...);
        $this->js_matcher = $this->js_matcher(...);
        $this->css_matcher = $this->css_matcher(...);
    }
    /**
     * Return the encoding that all output/input is expected to be encoded in.
     *
     * @return non-empty-string The lowercase encoding label (e.g. 'utf-8', 'iso-8859-1')
     * @since 2.0.0
     */
    public function get_encoding(): string
    {
        return $this->encoding;
    }
    /**
     * Escape a string for safe output in the HTML body context.
     *
     * Uses htmlspecialchars() internally. Safe for text between HTML tags.
     * Do NOT use for attribute values — use escape_html_attr() instead.
     *
     * @param string $string The raw, unescaped string to output in HTML body context
     * @return string The HTML-safe escaped string
     * @see escape_html_attr() For escaping inside HTML attribute values
     * @complexity O(n) where n is the length of $string
     * @since 2.0.0
     */
    public function escape_html(string $string): string
    {
        return htmlspecialchars($string, $this->html_special_chars_flags, $this->encoding);
    }
    /**
     * Escape a string for safe output inside HTML attribute values.
     *
     * Uses an extended set of characters beyond htmlspecialchars() to cover
     * unquoted and backtick-quoted attribute edge cases (per OWASP).
     * Characters beyond alphanumerics and safe punctuation are hex-entity encoded.
     *
     * @param string $string The raw, unescaped string to place inside an HTML attribute
     * @return string The attribute-safe escaped string
     * @throws Exception\RuntimeException If the string cannot be converted to UTF-8
     * @see escape_html() For escaping in the HTML body context
     * @complexity O(n) where n is the length of $string
     * @since 2.0.0
     */
    public function escape_html_attr(string $string): string
    {
        $string = $this->to_utf8($string);
        if ($string === '' || ctype_digit($string)) {
            return $string;
        }
        $result = preg_replace_callback('/[^a-z0-9,\.\-_]/iu', $this->html_attr_matcher, $string);
        assert(is_string($result));
        return $this->from_utf8($result);
    }
    /**
     * Escape a string for safe embedding inside a JavaScript string literal.
     *
     * Does not use json_encode(). Uses hex/unicode escaping to ensure the output
     * is safe even when HTML escaping was not applied on top. Backslash escaping
     * is intentionally avoided as it leaves the underlying character intact.
     *
     * @param string $string The raw, unescaped string to embed in JavaScript
     * @return string The JavaScript-safe escaped string
     * @throws Exception\RuntimeException If the string cannot be converted to UTF-8
     * @complexity O(n) where n is the length of $string
     * @since 2.0.0
     */
    public function escape_js(string $string): string
    {
        $string = $this->to_utf8($string);
        if ($string === '' || ctype_digit($string)) {
            return $string;
        }
        $result = preg_replace_callback('/[^a-z0-9,\._]/iu', $this->js_matcher, $string);
        assert(is_string($result));
        return $this->from_utf8($result);
    }
    /**
     * Escape a string for safe use as a URI component or query parameter value.
     *
     * Delegates to rawurlencode(), which implements RFC 3986. Use only for
     * individual URI sub-components (e.g. a single query parameter value),
     * NOT for encoding an entire URI.
     *
     * @param string $string The raw, unescaped URI subcomponent value
     * @return string The percent-encoded string safe for inclusion in a URI
     * @complexity O(n) where n is the length of $string
     * @since 2.0.0
     */
    public function escape_url(string $string): string
    {
        return rawurlencode($string);
    }
    /**
     * Escape a string for safe embedding inside a CSS property value or selector.
     *
     * Escapes everything except alphanumerics using CSS hex escape sequences.
     * Safe for use inside CSS string contexts or as unquoted identifier values.
     *
     * @param string $string The raw, unescaped string to embed in CSS
     * @return string The CSS-safe escaped string
     * @throws Exception\RuntimeException If the string cannot be converted to UTF-8
     * @complexity O(n) where n is the length of $string
     * @since 2.0.0
     */
    public function escape_css(string $string): string
    {
        $string = $this->to_utf8($string);
        if ($string === '' || ctype_digit($string)) {
            return $string;
        }
        $result = preg_replace_callback('/[^a-z0-9]/iu', $this->css_matcher, $string);
        assert(is_string($result));
        return $this->from_utf8($result);
    }
    /**
     * Callback function for preg_replace_callback that applies HTML Attribute
     * escaping to all matches.
     *
     * @param array<array-key, string> $matches
     */
    protected function html_attr_matcher(array $matches): string
    {
        $chr = $matches[0];
        $ord = ord($chr[0]);
        /**
         * The following replaces characters undefined in HTML with the
         * hex entity for the Unicode replacement character.
         */
        if ($ord <= 0x1f && $chr !== "\t" && $chr !== "\n" && $chr !== "\r" || $ord >= 0x7f && $ord <= 0x9f) {
            return '&#xFFFD;';
        }
        /**
         * Check if the current character to escape has a name entity we should
         * replace it with while grabbing the integer value of the character.
         */
        if (strlen($chr) > 1) {
            $chr = $this->convert_encoding($chr, 'UTF-32BE', 'UTF-8');
        }
        $hex = bin2hex($chr);
        $ord = hexdec($hex);
        if (isset(static::$html_named_entity_map[$ord])) {
            return '&' . static::$html_named_entity_map[$ord] . ';';
        }
        /**
         * Per OWASP recommendations, we'll use upper hex entities
         * for any other characters where a named entity does not exist.
         */
        if ($ord > 255) {
            return sprintf('&#x%04X;', $ord);
        }
        return sprintf('&#x%02X;', $ord);
    }
    /**
     * Callback function for preg_replace_callback that applies Javascript
     * escaping to all matches.
     *
     * @param array<array-key, string> $matches
     */
    protected function js_matcher(array $matches): string
    {
        $chr = $matches[0];
        if (strlen($chr) === 1) {
            return sprintf('\x%02X', ord($chr));
        }
        $chr = $this->convert_encoding($chr, 'UTF-16BE', 'UTF-8');
        $hex = strtoupper(bin2hex($chr));
        if (strlen($hex) <= 4) {
            return sprintf('\u%04s', $hex);
        }
        $high_surrogate = substr($hex, 0, 4);
        $low_surrogate = substr($hex, 4, 4);
        return sprintf('\u%04s\u%04s', $high_surrogate, $low_surrogate);
    }
    /**
     * Callback function for preg_replace_callback that applies CSS
     * escaping to all matches.
     *
     * @param array<array-key, string> $matches
     */
    protected function css_matcher(array $matches): string
    {
        $chr = $matches[0];
        if (strlen($chr) === 1) {
            $ord = ord($chr);
        } else {
            $chr = $this->convert_encoding($chr, 'UTF-32BE', 'UTF-8');
            $ord = hexdec(bin2hex($chr));
        }
        return sprintf('\%X ', $ord);
    }
    /**
     * Convert a string to UTF-8 from the configured base encoding.
     *
     * Used internally before applying regex-based escaping routines that
     * require UTF-8 input.
     *
     * @param string $string The string in the configured base encoding
     * @return string The string re-encoded as UTF-8
     * @throws Exception\RuntimeException If the string is not valid UTF-8 after conversion
     * @see get_encoding() For the configured base encoding
     */
    protected function to_utf8(string $string): string
    {
        if ($this->get_encoding() === 'utf-8') {
            $result = $string;
        } else {
            $result = $this->convert_encoding($string, 'UTF-8', $this->get_encoding());
        }
        if (!$this->is_utf8($result)) {
            throw new Exception\RuntimeException(sprintf('String to be escaped was not valid UTF-8 or could not be converted: %s', $result));
        }
        return $result;
    }
    /**
     * Convert a string from UTF-8 back to the configured base encoding.
     *
     * Used internally after regex-based escaping to restore the original encoding.
     * Returns the string unchanged when the configured encoding is already UTF-8.
     *
     * @param string $string The UTF-8 encoded string to convert back
     * @return string The string in the configured base encoding
     * @see to_utf8() The inverse operation
     */
    protected function from_utf8(string $string): string
    {
        if ($this->get_encoding() === 'utf-8') {
            return $string;
        }
        return $this->convert_encoding($string, $this->get_encoding(), 'UTF-8');
    }
    /**
     * Check whether a string is valid UTF-8.
     *
     * @param string $string The string to test for UTF-8 validity
     * @return bool True if $string is empty or passes the UTF-8 regex, false otherwise
     */
    protected function is_utf8(string $string): bool
    {
        return $string === '' || preg_match('/^./su', $string);
    }
    /**
     * Convert a string's encoding, wrapping mb_convert_encoding() with a safe fallback.
     *
     * Returns an empty string on conversion failure rather than a fatal error,
     * providing graceful degradation for invalid input sequences.
     *
     * @param string $string The string to convert
     * @param string $to The target encoding (e.g. 'UTF-8', 'UTF-32BE')
     * @param array<string>|string $from The source encoding or list of candidate encodings
     * @return string The converted string, or empty string on failure
     */
    protected function convert_encoding(string $string, string $to, array|string $from): string
    {
        $result = mb_convert_encoding($string, $to, $from);
        if ($result === false) {
            return '';
            // return non-fatal blank string on encoding errors from users
        }
        return $result;
    }
}
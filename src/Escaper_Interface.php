<?php

declare (strict_types=1);
namespace Laminas\Escaper;

/**
 * Interface for context-specific methods for use in secure output escaping.
 *
 * Each method targets a distinct output context (HTML body, HTML attributes,
 * JavaScript, URL components, CSS). Using the wrong escaper for a given context
 * can still result in XSS vulnerabilities, so context selection is critical.
 *
 * @since 2.0.0
 */
interface Escaper_Interface
{
    /**
     * Escape a string for the HTML Body context where there are very few characters
     * of special meaning. Internally this will use htmlspecialchars().
     *
     * @param string $string The raw string to embed in HTML body content
     * @return string The HTML-safe escaped string
     * @psalm-return ($string is non-empty-string ? non-empty-string : string)
     */
    public function escape_html(string $string): string;
    /**
     * Escape a string for the HTML Attribute context. We use an extended set of characters
     * to escape that are not covered by htmlspecialchars() to cover cases where an attribute
     * might be unquoted or quoted illegally (e.g. backticks are valid quotes for IE).
     *
     * @param string $string The raw string to embed inside an HTML attribute value
     * @return string The attribute-safe escaped string
     * @psalm-return ($string is non-empty-string ? non-empty-string : string)
     */
    public function escape_html_attr(string $string): string;
    /**
     * Escape a string for the Javascript context. This does not use json_encode(). An extended
     * set of characters are escaped beyond ECMAScript's rules for Javascript literal string
     * escaping in order to prevent misinterpretation of Javascript as HTML leading to the
     * injection of special characters and entities. The escaping used should be tolerant
     * of cases where HTML escaping was not applied on top of Javascript escaping correctly.
     * Backslash escaping is not used as it still leaves the escaped character as-is and so
     * is not useful in a HTML context.
     *
     * @param string $string The raw string to embed inside a JavaScript string literal
     * @return string The JavaScript-safe escaped string
     * @psalm-return ($string is non-empty-string ? non-empty-string : string)
     */
    public function escape_js(string $string): string;
    /**
     * Escape a string for the URI or Parameter contexts. This should not be used to escape
     * an entire URI - only a subcomponent being inserted. The function is a simple proxy
     * to rawurlencode() which now implements RFC 3986 since PHP 5.3 completely.
     *
     * @param string $string The raw URI subcomponent value (e.g. a single query parameter)
     * @return string The percent-encoded string
     * @psalm-return ($string is non-empty-string ? non-empty-string : string)
     */
    public function escape_url(string $string): string;
    /**
     * Escape a string for the CSS context. CSS escaping can be applied to any string being
     * inserted into CSS and escapes everything except alphanumerics.
     *
     * @param string $string The raw string to embed in a CSS property value or selector
     * @return string The CSS-safe escaped string
     * @psalm-return ($string is non-empty-string ? non-empty-string : string)
     */
    public function escape_css(string $string): string;
}

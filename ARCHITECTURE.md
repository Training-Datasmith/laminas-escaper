# Architecture: laminas-escaper

## Purpose

laminas-escaper provides context-aware output escaping to prevent Cross-Site Scripting (XSS)
vulnerabilities. It implements OWASP-recommended escaping strategies for five distinct
output contexts: HTML body, HTML attributes, JavaScript, CSS, and URLs.

## Directory Structure

```
src/
  Escaper.php               # Concrete implementation; final class
  Escaper_Interface.php     # Public contract defining the five escape methods
  Exception/
    Exception_Interface.php          # Marker interface for all library exceptions
    Invalid_Argument_Exception.php   # Thrown for unsupported encoding arguments
    Runtime_Exception.php            # Thrown when a string cannot be converted to UTF-8
test/
  Escaper_Test.php          # PHPUnit test suite
  StaticAnalysis/           # Psalm return-type assertions
```

## Key Design Decisions

- **Context segregation**: Each output context has a dedicated method. Mixing contexts
  (e.g. using `escape_html()` inside a `<script>` tag) is still an XSS risk.
- **Encoding normalisation**: All regex escaping operates on UTF-8 internally.
  The constructor accepts an alternate encoding; strings are converted to UTF-8
  before escaping and back after (`to_utf8` / `from_utf8`).
- **No JSON encoding for JS**: `escape_js()` uses hex/unicode escaping rather than
  `json_encode()` to avoid misinterpretation when HTML escaping is absent.
- **OWASP character ranges**: The HTML attribute and JS matchers escape all characters
  outside safe alphanumeric + immune-char ranges, not just HTML special chars.
- **Final class**: `Escaper` is declared `@final` to prevent unsafe subclassing that
  could bypass the escaping logic.

## Extension Points

- Implement `Escaper_Interface` to provide a custom escaper (e.g. one backed by
  a native extension) while remaining compatible with all type-hinted consumers.

## Dependency Flow

```
Escaper implements Escaper_Interface
Escaper uses ext-mbstring (mb_convert_encoding)
Escaper uses ext-ctype   (ctype_digit)
Escaper throws Exception\InvalidArgumentException | Exception\RuntimeException
```

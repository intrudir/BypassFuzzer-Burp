package com.bypassfuzzer.core.urlvalidation;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

/**
 * Generates Unicode compatibility variants of an input string for the
 * "Normalization attack" URL-validation bypass class.
 *
 * Many servers compare the raw URL/host string against a deny or allow list
 * BEFORE the URL parser / string layer applies Unicode normalization. If the
 * normalizer uses NFKC (or any compatibility-aware form) it will map Unicode
 * "presentation form" characters — fullwidth Latin, half-width ASCII, Roman
 * numerals, Arabic presentation forms, etc. — back to their plain ASCII
 * equivalents. A payload like "ａdmin" (fullwidth 'a') slips past a literal
 * "admin" compare and still resolves to admin after normalization.
 *
 * This helper emits:
 *   - all-lower-fullwidth Latin
 *   - all-upper-fullwidth Latin
 *   - a per-letter single-position variant (one char at a time replaced)
 * in that order, deduped.
 */
public final class UnicodeCompatibilityVariants {

    private UnicodeCompatibilityVariants() {}

    /**
     * Return compatibility-form variants of {@code input}. The input itself is
     * not included. Only ASCII letters and digits are substituted; everything
     * else (dots, slashes, hyphens, colons, etc.) stays literal so hostnames
     * keep their shape.
     */
    public static List<String> fullwidthVariants(String input) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        if (input == null || input.isEmpty()) {
            return new ArrayList<>(out);
        }

        out.add(toFullwidth(input));
        String lower = input.toLowerCase();
        String upper = input.toUpperCase();
        if (!lower.equals(input)) {
            out.add(toFullwidth(lower));
        }
        if (!upper.equals(input)) {
            out.add(toFullwidth(upper));
        }

        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            char fw = fullwidthChar(c);
            if (fw != c) {
                out.add(input.substring(0, i) + fw + input.substring(i + 1));
            }
        }

        // Remove the verbatim input if it sneaked in (all-ASCII, no substitutions).
        out.remove(input);
        return new ArrayList<>(out);
    }

    private static String toFullwidth(String s) {
        StringBuilder b = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            b.append(fullwidthChar(s.charAt(i)));
        }
        return b.toString();
    }

    /**
     * Map a single ASCII letter/digit to its fullwidth (U+FF00-block) form.
     * Non-ASCII input and non-letter/digit chars pass through unchanged so URL
     * delimiters, dots, hyphens, and Unicode chars already in the input remain
     * where they were.
     */
    static char fullwidthChar(char c) {
        if (c >= 'A' && c <= 'Z') return (char) (0xFF21 + (c - 'A'));
        if (c >= 'a' && c <= 'z') return (char) (0xFF41 + (c - 'a'));
        if (c >= '0' && c <= '9') return (char) (0xFF10 + (c - '0'));
        return c;
    }
}

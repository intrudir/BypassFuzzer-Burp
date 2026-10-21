package com.bypassfuzzer.burp.core.urlvalidation;
import com.bypassfuzzer.core.urlvalidation.UnicodeCompatibilityVariants;

import org.junit.jupiter.api.Test;

import java.text.Normalizer;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UnicodeCompatibilityVariantsTest {

    @Test
    void emptyInputReturnsEmpty() {
        assertTrue(UnicodeCompatibilityVariants.fullwidthVariants("").isEmpty());
        assertTrue(UnicodeCompatibilityVariants.fullwidthVariants(null).isEmpty());
    }

    @Test
    void asciiOnlyInputProducesFullwidthForm() {
        List<String> variants = UnicodeCompatibilityVariants.fullwidthVariants("admin");
        // all-fullwidth 'admin'
        String expected = "\uff41\uff44\uff4d\uff49\uff4e";
        assertTrue(variants.contains(expected), "expected all-fullwidth 'admin'; got " + variants);
    }

    @Test
    void variantsNfkcNormalizeBackToOriginal() {
        // This is the property the attack relies on — the compatibility
        // variants must collapse back to the original ASCII under NFKC.
        String input = "alice";
        for (String variant : UnicodeCompatibilityVariants.fullwidthVariants(input)) {
            String normalized = Normalizer.normalize(variant, Normalizer.Form.NFKC);
            assertTrue(
                normalized.equalsIgnoreCase(input),
                "variant " + variant + " should NFKC-normalize to " + input + " (got " + normalized + ")"
            );
        }
    }

    @Test
    void perPositionSingleReplacementEmitted() {
        // For 'admin', one of the variants should be 'ａdmin' (only the first
        // letter fullwidth).
        List<String> variants = UnicodeCompatibilityVariants.fullwidthVariants("admin");
        String singleFirst = "\uff41" + "dmin";
        assertTrue(variants.contains(singleFirst),
            "expected single-position variant '\uff41dmin'; got " + variants);
    }

    @Test
    void nonLetterCharsPreserved() {
        List<String> variants = UnicodeCompatibilityVariants.fullwidthVariants("sub.host.com");
        for (String v : variants) {
            assertTrue(v.contains("."), "dots should be preserved in " + v);
        }
    }

    @Test
    void originalInputNotIncluded() {
        List<String> variants = UnicodeCompatibilityVariants.fullwidthVariants("admin");
        assertFalse(variants.contains("admin"), "original ASCII input must not be in variants set");
    }
}

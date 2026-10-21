package com.bypassfuzzer.burp.http;
import com.bypassfuzzer.core.http.ConfiguredHeaderParser;
import com.bypassfuzzer.core.http.ConfiguredHeader;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ConfiguredHeaderParserTest {

    @Test
    void preservesDuplicatesOrderAndEmptyValues() {
        List<ConfiguredHeader> parsed = ConfiguredHeaderParser.parse(
            "Authorization: Bearer one\nX-Empty:\nauthorization: Bearer two\nX-Whitespace:  intentional \n");

        assertEquals(List.of(
            new ConfiguredHeader("Authorization", "Bearer one"),
            new ConfiguredHeader("X-Empty", ""),
            new ConfiguredHeader("authorization", "Bearer two"),
            new ConfiguredHeader("X-Whitespace", " intentional ")
        ), parsed);
    }

    @Test
    void rejectsMalformedAndInjectedHeaderLinesWithLineNumber() {
        IllegalArgumentException missingColon = assertThrows(IllegalArgumentException.class,
            () -> ConfiguredHeaderParser.parse("X-Good: yes\nnot a header"));
        IllegalArgumentException control = assertThrows(IllegalArgumentException.class,
            () -> ConfiguredHeaderParser.parse("X-Test: bad" + (char) 1 + "value"));

        assertEquals("Header line 2: expected Name: value.", missingColon.getMessage());
        assertEquals("Header line 1: header value contains a forbidden control character.", control.getMessage());
    }
}

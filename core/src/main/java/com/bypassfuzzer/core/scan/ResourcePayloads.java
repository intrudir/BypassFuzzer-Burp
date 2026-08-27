package com.bypassfuzzer.core.scan;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.List;

final class ResourcePayloads {
    private ResourcePayloads() {}

    static List<String> load(String name) {
        String path = "/payloads/" + name;
        InputStream stream = ResourcePayloads.class.getResourceAsStream(path);
        if (stream == null) throw new IllegalStateException("Missing bundled payload resource: " + path);
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            return reader.lines().map(String::trim).filter(line -> !line.isEmpty() && !line.startsWith("#")).toList();
        } catch (Exception exception) {
            throw new IllegalStateException("Unable to read bundled payload resource: " + path, exception);
        }
    }
}

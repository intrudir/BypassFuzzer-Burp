package com.bypassfuzzer.burp.core.coverage;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Path;
import java.nio.file.Files;

import static org.junit.jupiter.api.Assertions.*;

class OpenApiImportAuditTest {
    @TempDir Path directory;

    private static final String SPEC = """
        {"openapi":"3.0.3", "servers":[{"url":"http://assets.example.test"}], "paths":{
          "/assets":{"get":{"parameters":[
            {"name":"tenant.id","in":"query","required":true,"schema":{"type":"integer"}},
            {"name":"Sort","in":"query","schema":{"type":"array","items":{"type":"object","properties":{
              "column":{"type":"string","enum":["created"]},"direction":{"type":"string","enum":["asc","desc"]}}}}}
          ]}},
          "/assets/{id}":{"put":{"parameters":[
            {"name":"id","in":"path","required":true,"schema":{"type":"string","format":"uuid","default":null}},
            {"name":"FileName","in":"query","required":true,"schema":{"type":"string"}}
          ]}},
          "/assets/{id}/restore":{"patch":{"parameters":[
            {"name":"id","in":"path","required":true,"schema":{"type":"string","format":"uuid","default":null}}
          ]}}
        }}
        """;

    @Test
    void checksEveryOperationPolicyOriginAndControlWithoutSendingTraffic() throws Exception {
        var report = OpenApiImportAudit.audit(SPEC, "https://assets.example.test/docs/openapi.json", directory);
        assertEquals(3, report.get("operations"));
        assertEquals(24, report.get("scenarios"));
        assertEquals(72, report.get("checkedRequests"));
        assertEquals(0, report.get("networkRequestsSent"));
        try (var requests = Files.walk(directory)) {
            assertEquals(72, requests.filter(path -> path.toString().endsWith(".http")).count());
        }
    }

    @Test
    void independentlyRejectsInvalidUuidAndEnumExamples() {
        String invalidUuid = SPEC.replace("\"default\":null", "\"example\":\"1\"");
        assertThrows(IllegalArgumentException.class, () -> OpenApiImportAudit.audit(invalidUuid,
            "https://assets.example.test/docs/openapi.json", directory.resolve("invalid-uuid")));
        String invalidEnum = SPEC.replace("\"enum\":[\"created\"]", "\"enum\":[\"created\"],\"example\":\"invalid-column\"");
        assertThrows(AssertionError.class, () -> OpenApiImportAudit.audit(invalidEnum,
            "https://assets.example.test/docs/openapi.json", directory.resolve("invalid-enum")));
    }
}

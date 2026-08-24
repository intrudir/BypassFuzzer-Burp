package com.bypassfuzzer.burp.core.attacks;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static com.bypassfuzzer.burp.testsupport.AttackTestSupport.api;
import static com.bypassfuzzer.burp.testsupport.AttackTestSupport.countOccurrences;
import static com.bypassfuzzer.burp.testsupport.AttackTestSupport.findByPayload;
import static com.bypassfuzzer.burp.testsupport.AttackTestSupport.nullResponseExecutor;
import static com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.request;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AttackStrategyBehaviorTest {

    @Test
    void extensionAttackAttachesExtensionBeforeOriginalTrailingSlash() {
        ExtensionAttack attack = new ExtensionAttack("https://example.com/yamplus_api/extreport/");
        List<AttackResult> results = new ArrayList<>();

        attack.execute(
            api(),
            request("/yamplus_api/extreport/", "", "GET", null, ""),
            "https://example.com/yamplus_api/extreport/",
            results::add,
            () -> true,
            null,
            nullResponseExecutor()
        );

        assertTrue(results.stream()
            .map(result -> result.getRequest().path())
            .anyMatch("/yamplus_api/extreport.config"::equals));
        assertTrue(results.stream()
            .map(result -> result.getRequest().path())
            .noneMatch("/yamplus_api/extreport/.config"::equals));
    }

    @Test
    void extensionAttackPreservesQueryAfterRemovingTrailingSlash() {
        ExtensionAttack attack = new ExtensionAttack("https://example.com/report/?format=full");
        List<AttackResult> results = new ArrayList<>();

        attack.execute(
            api(),
            request("/report/", "format=full", "GET", null, ""),
            "https://example.com/report/?format=full",
            results::add,
            () -> true,
            null,
            nullResponseExecutor()
        );

        assertTrue(results.stream()
            .map(result -> result.getRequest().path())
            .anyMatch("/report.config?format=full"::equals));
    }

    @Test
    void pathAttackSendsMatrixJsonSuffixForBlockedEndpointMiss() {
        // Client miss: GET /something returned 401, but GET /something;.json
        // returned 200 with the protected data. The path attack must send that
        // exact mutated request when a tester targets the blocked endpoint.
        PathAttack attack = new PathAttack("https://victim.com/something");
        List<AttackResult> results = new ArrayList<>();

        attack.execute(
            api(),
            request("/something", "", "GET", null, ""),
            "https://victim.com/something",
            results::add,
            () -> true,
            null,
            nullResponseExecutor()
        );

        assertTrue(results.stream()
            .map(result -> result.getRequest().path())
            .anyMatch("/something;.json"::equals));
        assertTrue(results.stream()
            .map(result -> result.getRequest().path())
            .anyMatch("/something;.html"::equals));
        assertTrue(results.stream()
            .map(result -> result.getRequest().path())
            .anyMatch("/something;.bak"::equals));
        assertTrue(results.stream()
            .map(result -> result.getRequest().path())
            .anyMatch("/something;.tar.gz"::equals));
    }

    @Test
    void contentTypeAttackPreservesDuplicateBodyParametersAcrossConversions() {
        ContentTypeAttack attack = new ContentTypeAttack();
        List<AttackResult> results = new ArrayList<>();

        attack.execute(
            api(),
            request("/admin", "", "POST", "application/x-www-form-urlencoded", "debug=one&debug=two&role=user"),
            "https://example.com/admin",
            results::add,
            () -> true,
            null,
            nullResponseExecutor()
        );

        AttackResult jsonResult = findByPayload(results, "Content-Type: JSON");
        assertNotNull(jsonResult);
        assertEquals("{\"debug\":\"one\",\"debug\":\"two\",\"role\":\"user\"}", jsonResult.getRequest().bodyToString());

        AttackResult multipartResult = findByPayload(results, "Content-Type: multipart/form-data");
        assertNotNull(multipartResult);
        assertEquals(2, countOccurrences(multipartResult.getRequest().bodyToString(), "name=\"debug\""));

        AttackResult wildcardResult = findByPayload(results, "Content-Type: */*");
        assertNotNull(wildcardResult);
        assertEquals("*/*", wildcardResult.getRequest().headerValue("Content-Type"));
    }

    @Test
    void contentTypeAttackFlattensNestedXmlPathsWithoutSyntheticRootNoise() {
        ContentTypeAttack attack = new ContentTypeAttack();
        List<AttackResult> results = new ArrayList<>();

        attack.execute(
            api(),
            request(
                "/admin",
                "",
                "POST",
                "application/xml",
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><root><meta><role>user</role></meta><users><user><role>admin</role></user><user><role>auditor</role></user></users></root>"
            ),
            "https://example.com/admin",
            results::add,
            () -> true,
            null,
            nullResponseExecutor()
        );

        AttackResult jsonResult = findByPayload(results, "Content-Type: JSON");
        assertNotNull(jsonResult);
        assertTrue(jsonResult.getRequest().bodyToString().contains("\"meta.role\":\"user\""));
        assertTrue(jsonResult.getRequest().bodyToString().contains("\"users.user.role\":\"admin\""));
        assertTrue(jsonResult.getRequest().bodyToString().contains("\"users.user[1].role\":\"auditor\""));
        assertTrue(!jsonResult.getRequest().bodyToString().contains("\"root[0].users[0].user[1].role[0]\""));
    }

    @Test
    void contentTypeAttackFlattensNestedJsonArraysForMultipartConversion() {
        ContentTypeAttack attack = new ContentTypeAttack();
        List<AttackResult> results = new ArrayList<>();

        attack.execute(
            api(),
            request(
                "/admin",
                "",
                "POST",
                "application/json",
                "{\"users\":[{\"role\":\"admin\"},{\"role\":\"auditor\"}],\"tags\":[\"red\",\"blue\"]}"
            ),
            "https://example.com/admin",
            results::add,
            () -> true,
            null,
            nullResponseExecutor()
        );

        AttackResult multipartResult = findByPayload(results, "Content-Type: multipart/form-data");
        assertNotNull(multipartResult);
        assertTrue(multipartResult.getRequest().bodyToString().contains("name=\"users[0].role\""));
        assertTrue(multipartResult.getRequest().bodyToString().contains("name=\"users[1].role\""));
        assertTrue(multipartResult.getRequest().bodyToString().contains("name=\"tags[0]\""));
        assertTrue(multipartResult.getRequest().bodyToString().contains("name=\"tags[1]\""));
    }

    @Test
    void contentTypeAttackPreservesRepeatedMultipartNamesAcrossConversions() {
        ContentTypeAttack attack = new ContentTypeAttack();
        List<AttackResult> results = new ArrayList<>();
        String boundary = "----Boundary123";
        String body =
            "--" + boundary + "\r\n" +
            "Content-Disposition: form-data; name=\"debug\"\r\n\r\n" +
            "one\r\n" +
            "--" + boundary + "\r\n" +
            "Content-Disposition: form-data; name=\"debug\"\r\n\r\n" +
            "two\r\n" +
            "--" + boundary + "\r\n" +
            "Content-Disposition: form-data; name=\"role\"\r\n\r\n" +
            "user\r\n" +
            "--" + boundary + "--\r\n";

        attack.execute(
            api(),
            request("/admin", "", "POST", "multipart/form-data; boundary=\"" + boundary + "\"", body),
            "https://example.com/admin",
            results::add,
            () -> true,
            null,
            nullResponseExecutor()
        );

        AttackResult urlEncodedResult = findByPayload(results, "Content-Type: URL-encoded");
        assertNotNull(urlEncodedResult);
        assertEquals("debug=one&debug=two&role=user", urlEncodedResult.getRequest().bodyToString());

        AttackResult jsonResult = findByPayload(results, "Content-Type: JSON");
        assertNotNull(jsonResult);
        assertEquals("{\"debug\":\"one\",\"debug\":\"two\",\"role\":\"user\"}", jsonResult.getRequest().bodyToString());
    }

    @Test
    void encodingAttackTargetsNestedJsonFieldsIndependently() {
        EncodingAttack attack = new EncodingAttack();
        List<AttackResult> results = new ArrayList<>();

        attack.execute(
            api(),
            request(
                "/admin",
                "",
                "POST",
                "application/json",
                "{\"meta\":{\"role\":\"user\"},\"users\":[{\"role\":\"admin\"}]}"
            ),
            "https://example.com/admin",
            results::add,
            () -> true,
            null,
            nullResponseExecutor()
        );

        boolean mutatedMetaOnly = results.stream()
            .map(result -> result.getRequest().bodyToString())
            .anyMatch(body -> body.contains("\"users\":[{\"role\":\"admin\"}]")
                && !body.contains("\"meta\":{\"role\":\"user\"}")
                && countOccurrences(body, "\"role\":") == 1);

        boolean mutatedUsersOnly = results.stream()
            .map(result -> result.getRequest().bodyToString())
            .anyMatch(body -> body.contains("\"meta\":{\"role\":\"user\"}")
                && !body.contains("\"users\":[{\"role\":\"admin\"}]")
                && countOccurrences(body, "\"role\":") == 1);

        assertTrue(mutatedMetaOnly);
        assertTrue(mutatedUsersOnly);
    }

    @Test
    void encodingAttackTargetsNestedXmlFieldsIndependently() {
        EncodingAttack attack = new EncodingAttack();
        List<AttackResult> results = new ArrayList<>();

        attack.execute(
            api(),
            request(
                "/admin",
                "",
                "POST",
                "application/xml",
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><root><meta><role>user</role></meta><users><user><role>admin</role></user></users></root>"
            ),
            "https://example.com/admin",
            results::add,
            () -> true,
            null,
            nullResponseExecutor()
        );

        boolean mutatedMetaOnly = results.stream()
            .map(result -> result.getRequest().bodyToString())
            .anyMatch(body -> body.contains("<users><user><role>admin</role></user></users>")
                && !body.contains("<meta><role>user</role></meta>"));

        boolean mutatedUsersOnly = results.stream()
            .map(result -> result.getRequest().bodyToString())
            .anyMatch(body -> body.contains("<meta><role>user</role></meta>")
                && !body.contains("<users><user><role>admin</role></user></users>"));

        assertTrue(mutatedMetaOnly);
        assertTrue(mutatedUsersOnly);
    }

    @Test
    void encodingAttackTargetsDuplicateQueryParametersByOccurrence() {
        EncodingAttack attack = new EncodingAttack();
        List<AttackResult> results = new ArrayList<>();

        attack.execute(
            api(),
            request("/admin", "debug=one&debug=two&role=safe", "GET", null, ""),
            "https://example.com/admin?debug=one&debug=two&role=safe",
            results::add,
            () -> true,
            null,
            nullResponseExecutor()
        );

        boolean firstDuplicateOnlyMutated = results.stream()
            .filter(result -> result.getPayload().contains("Param value") && result.getPayload().contains("(query)"))
            .map(result -> result.getRequest().path())
            .anyMatch(path -> path.matches("/admin\\?debug=[^&]+&debug=two&role=safe")
                && !"/admin?debug=one&debug=two&role=safe".equals(path));

        boolean secondDuplicateOnlyMutated = results.stream()
            .filter(result -> result.getPayload().contains("Param value") && result.getPayload().contains("(query)"))
            .map(result -> result.getRequest().path())
            .anyMatch(path -> path.matches("/admin\\?debug=one&debug=[^&]+&role=safe")
                && !"/admin?debug=one&debug=two&role=safe".equals(path));

        assertTrue(firstDuplicateOnlyMutated);
        assertTrue(secondDuplicateOnlyMutated);
    }
}

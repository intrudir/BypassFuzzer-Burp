package com.bypassfuzzer.core.scan;

import com.bypassfuzzer.core.http.*;
import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

/** Behavioral contracts retained from the master's former transport-bound strategies. */
class MasterBypassBehaviorTest {
    private HttpRequestData request(String raw) {
        return new RawHttpRequestParser().parse(raw.getBytes(StandardCharsets.UTF_8), TargetOrigin.parse("https://example.com"));
    }
    private List<PlannedRequest> plan(HttpRequestData request, AttackFamily family) {
        return new BypassPlanner().plan(request, Set.of(family), true, Integer.MAX_VALUE);
    }

    @Test void bodyConversionsPreserveDuplicateParameters() {
        var input = request("POST /admin HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\ndebug=one&debug=two&role=user");
        var plans = plan(input, AttackFamily.CONTENT_TYPE);
        var json = plans.stream().filter(p -> p.payload().equals("Content-Type conversion: JSON")).findFirst().orElseThrow().request();
        assertEquals("{\"debug\":\"one\",\"debug\":\"two\",\"role\":\"user\"}", new String(json.body(), StandardCharsets.UTF_8));
        var multipart = plans.stream().filter(p -> p.payload().equals("Content-Type conversion: MULTIPART")).findFirst().orElseThrow().request();
        assertEquals(2, new String(multipart.body(), StandardCharsets.UTF_8).split("name=\"debug\"", -1).length - 1);
    }

    @Test void bodyConversionsIncludeQueryInputsAndUsePostWhenNeeded() {
        var input = request("GET /preferences?debug=false&role=user HTTP/1.1\r\nHost: example.com\r\n\r\n");
        var json = plan(input, AttackFamily.CONTENT_TYPE).stream()
            .filter(p -> p.payload().equals("Content-Type conversion: JSON")).findFirst().orElseThrow().request();
        assertEquals("POST", json.method());
        assertEquals("/preferences", json.rawTarget());
        assertEquals("{\"debug\":\"false\",\"role\":\"user\"}", new String(json.body(), StandardCharsets.UTF_8));
    }

    @Test void nestedXmlRetainsTheMasterFlatteningRules() {
        var input = request("POST /admin HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/xml\r\n\r\n"
            + "<root><meta><role>user</role></meta><users><user><role>admin</role></user><user><role>auditor</role></user></users></root>");
        String body = new String(plan(input, AttackFamily.CONTENT_TYPE).stream()
            .filter(p -> p.payload().equals("Content-Type conversion: JSON")).findFirst().orElseThrow().request().body(), StandardCharsets.UTF_8);
        assertTrue(body.contains("\"meta.role\":\"user\""));
        assertTrue(body.contains("\"users.user[1].role\":\"auditor\""));
        assertFalse(body.contains("root[0].users"));
    }

    @Test void methodMutationsMoveParametersBetweenQueryAndBody() {
        var input = request("GET /admin?debug=one&debug=two HTTP/1.1\r\nHost: example.com\r\n\r\n");
        var post = plan(input, AttackFamily.VERB).stream().filter(p -> p.payload().equals("POST (params query→body)"))
            .findFirst().orElseThrow().request();
        assertEquals("/admin", post.rawTarget());
        assertEquals("debug=one&debug=two", new String(post.body(), StandardCharsets.UTF_8));
        assertEquals("application/x-www-form-urlencoded", post.firstHeader("Content-Type").orElseThrow());
    }

    @Test void queryAndCookieMutationsPreserveDuplicateSlots() {
        var input = request("GET /admin?debug=one&debug=two&untouched=ok HTTP/1.1\r\nHost: example.com\r\nCookie: debug=one; debug=two; session=owned\r\n\r\n");
        var query = plan(input, AttackFamily.PARAM).stream().filter(p -> p.payload().equals("debug=true")).findFirst().orElseThrow().request();
        assertEquals("debug=true&debug=true&untouched=ok", query.query());
        var cookie = plan(input, AttackFamily.COOKIE).stream().filter(p -> p.payload().equals("debug=true")).findFirst().orElseThrow().request();
        assertEquals("debug=true; debug=true; session=owned", cookie.firstHeader("Cookie").orElseThrow());
    }

    @Test void encodingCoversBodyParameterNamesAndValues() {
        var input = request("POST /admin HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{\"role\":\"user\"}");
        var plans = plan(input, AttackFamily.ENCODING);
        assertTrue(plans.stream().anyMatch(p -> p.payload().startsWith("Param name url (BODY)")));
        assertTrue(plans.stream().anyMatch(p -> p.payload().startsWith("Param value url (BODY)")));
    }

    @Test void protocolsAreNotCollapsedByWireMessageDeduplication() {
        var input = request("GET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n");
        var protocols = plan(input, AttackFamily.PROTOCOL).stream().map(p -> p.request().protocol()).toList();
        assertEquals(List.of(HttpProtocol.HTTP_2, HttpProtocol.HTTP_1, HttpProtocol.HTTP_1_0, HttpProtocol.HTTP_0_9), protocols);
    }
}

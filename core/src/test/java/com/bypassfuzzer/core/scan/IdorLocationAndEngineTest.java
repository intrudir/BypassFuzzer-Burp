package com.bypassfuzzer.core.scan;

import com.bypassfuzzer.core.http.HttpHeader;
import com.bypassfuzzer.core.http.HttpProtocol;
import com.bypassfuzzer.core.http.HttpRequestData;
import com.bypassfuzzer.core.http.HttpResponseData;
import com.bypassfuzzer.core.http.RawHttpRequestParser;
import com.bypassfuzzer.core.http.TargetOrigin;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class IdorLocationAndEngineTest {
    private HttpRequestData request() {
        String body = "{\"name\":\"project-619\",\"namespaceId\":\"619\"}";
        String raw = "POST /v3/api/v3/namespaces/619/projects HTTP/1.1\r\nHost: example.invalid\r\n"
            + "Authorization: Bearer dummy-619-token\r\nCookie: auth_token=dummy-619-token\r\n"
            + "Content-Type: application/json\r\n\r\n" + body;
        return new RawHttpRequestParser().parse(raw.getBytes(StandardCharsets.UTF_8), TargetOrigin.parse("https://example.invalid"));
    }

    @Test
    void selectedPathSlotPreservesVersionsCredentialsAndBody() {
        HttpRequestData input = request();
        List<IdentifierLocation> found = IdentifierLocation.discover(input, "619");
        assertEquals(List.of("path:5", "json:/namespaceId"), found.stream().map(IdentifierLocation::key).toList());
        List<PlannedRequest> plan = new IdorPlanner().plan(input,
            new IdorPlanOptions("619", "3", "path:5", Set.of("idor.path.suffix_formats"), 10, false));
        assertEquals("/v3/api/v3/namespaces/3/projects", plan.get(1).request().rawTarget());
        assertEquals("/v3/api/v3/namespaces/3.json/projects", plan.get(2).request().rawTarget());
        assertNotEquals(plan.get(1).request().toRaw(), plan.get(2).request().toRaw());
        for (PlannedRequest item : plan) {
            assertTrue(item.request().rawTarget().startsWith("/v3/api/v3/namespaces/"));
            assertEquals("Bearer dummy-619-token", item.request().firstHeader("Authorization").orElseThrow());
            assertEquals("auth_token=dummy-619-token", item.request().firstHeader("Cookie").orElseThrow());
            assertEquals("{\"name\":\"project-619\",\"namespaceId\":\"619\"}",
                new String(item.request().body(), StandardCharsets.UTF_8));
        }
    }

    @Test
    void locationSpansPointToOnlyTheSelectedRequestValues() {
        HttpRequestData input = request();
        List<IdentifierLocation> locations = IdentifierLocation.discover(input, "619");
        String raw = input.toRaw();
        var pathSpan = IdentifierLocationSpan.find(input, locations.get(0)).orElseThrow();
        var jsonSpan = IdentifierLocationSpan.find(input, locations.get(1)).orElseThrow();
        assertEquals("619", raw.substring(pathSpan.start(), pathSpan.end()));
        assertEquals("619", raw.substring(jsonSpan.start(), jsonSpan.end()));
        assertTrue(pathSpan.start() < raw.indexOf("Authorization:"));
        assertTrue(jsonSpan.start() > raw.indexOf("\r\n\r\n"));
        assertNotEquals(raw.indexOf("619", raw.indexOf("Authorization:")), jsonSpan.start());
    }

    @Test
    void locationSpansResolveDuplicatePairsAndNestedJsonWithEscapes() {
        String raw = "POST /items?id=619&id=619 HTTP/1.1\r\nHost: example.invalid\r\n"
            + "Content-Type: application/x-www-form-urlencoded\r\n\r\nid=619&id=619";
        HttpRequestData form = new RawHttpRequestParser().parse(raw.getBytes(StandardCharsets.UTF_8),
            TargetOrigin.parse("https://example.invalid"));
        var locations = IdentifierLocation.discover(form, "619");
        assertEquals(List.of("query:id#0", "query:id#1", "form:id#0", "form:id#1"),
            locations.stream().map(IdentifierLocation::key).toList());
        for (int i = 0; i < locations.size(); i++) {
            var span = IdentifierLocationSpan.find(form, locations.get(i)).orElseThrow();
            assertEquals("619", form.toRaw().substring(span.start(), span.end()));
            for (int j = 0; j < i; j++)
                assertTrue(span.start() > IdentifierLocationSpan.find(form, locations.get(j)).orElseThrow().start());
        }

        String jsonRaw = "POST /items HTTP/1.1\r\nHost: example.invalid\r\nContent-Type: application/json\r\n\r\n"
            + "{\"meta\":{\"ignore\":\"619\"},\"list\":[{\"id\":\"\\u003619\"},{\"id\":\"619\"}]}";
        HttpRequestData json = new RawHttpRequestParser().parse(jsonRaw.getBytes(StandardCharsets.UTF_8),
            TargetOrigin.parse("https://example.invalid"));
        var jsonLocations = IdentifierLocation.discover(json, "619");
        assertEquals(List.of("json:/meta/ignore", "json:/list/0/id", "json:/list/1/id"),
            jsonLocations.stream().map(IdentifierLocation::key).toList());
        var escaped = IdentifierLocationSpan.find(json, jsonLocations.get(1)).orElseThrow();
        assertEquals("\\u003619", json.toRaw().substring(escaped.start(), escaped.end()));
        var last = IdentifierLocationSpan.find(json, jsonLocations.get(2)).orElseThrow();
        assertEquals("619", json.toRaw().substring(last.start(), last.end()));

        String unicodeRaw = "POST /items HTTP/1.1\r\nHost: example.invalid\r\nContent-Type: application/json\r\n\r\n"
            + "{\"label\":\"café\",\"id\":\"619\"}";
        HttpRequestData unicode = new RawHttpRequestParser().parse(unicodeRaw.getBytes(StandardCharsets.UTF_8),
            TargetOrigin.parse("https://example.invalid"));
        var unicodeSpan = IdentifierLocationSpan.find(unicode,
            IdentifierLocation.discover(unicode, "619").get(0)).orElseThrow();
        assertEquals("619", unicode.toRaw().substring(unicodeSpan.start(), unicodeSpan.end()));
    }

    @Test
    void selectedJsonSlotMutatesOnlyThatField() {
        List<PlannedRequest> plan = new IdorPlanner().plan(request(),
            new IdorPlanOptions("619", "3", "json:/namespaceId",
                Set.of("idor.body.wildcard_identifiers"), 1, false));
        assertEquals(3, plan.size());
        assertEquals("/v3/api/v3/namespaces/619/projects", plan.get(2).request().rawTarget());
        assertTrue(new String(plan.get(2).request().body(), StandardCharsets.UTF_8)
            .contains("\"namespaceId\":\"*\""));
    }

    @Test
    void uniqueCreateFieldIsDistinctForBothControlsAndEachMutation() {
        List<PlannedRequest> plan = new IdorPlanner().plan(request(),
            new IdorPlanOptions("619", "3", "path:5", Set.of("idor.path.suffix_formats"),
                2, false, "/name", "testrun"));
        assertEquals(4, plan.size());
        for (int index = 0; index < plan.size(); index++)
            assertTrue(new String(plan.get(index).request().body(), StandardCharsets.UTF_8)
                .contains("project-619-bf-testrun-" + (index + 1)));
        assertThrows(IllegalArgumentException.class, () -> new IdorPlanner().plan(request(),
            new IdorPlanOptions("619", "3", "path:5", Set.of(), 1, false,
                "/namespaceId/missing", "testrun")));
    }

    @Test
    void jsonPollutionFamilyProducesDuplicateKeysAtSelectedField() {
        List<PlannedRequest> plan = new IdorPlanner().plan(request(),
            new IdorPlanOptions("619", "3", "json:/namespaceId",
                Set.of("idor.body.json_parameter_pollution"), 2, false));
        assertEquals(4, plan.size());
        String body = new String(plan.get(2).request().body(), StandardCharsets.UTF_8);
        assertTrue(body.contains("\"namespaceId\":\"619\",\"namespaceId\":\"3\""));
        assertEquals("/v3/api/v3/namespaces/619/projects", plan.get(2).request().rawTarget());
    }

    @Test
    void queryPollutionRetainsTargetAndAppendsAuthorizedValue() {
        List<PlannedRequest> plan = new IdorPlanner().plan(request(),
            new IdorPlanOptions("619", "3", "path:5",
                Set.of("idor.query.parameter_pollution"), 2, false));
        assertEquals(4, plan.size());
        assertEquals("/v3/api/v3/namespaces/3/projects?id=619", plan.get(2).request().rawTarget());
        assertEquals("/v3/api/v3/namespaces/3/projects?id=619&id=3",
            plan.get(3).request().rawTarget());
    }

    @Test
    void mutationUsesTargetBaselineAndRecordsCandidate() throws Exception {
        HttpRequestData input = request();
        ScanOptions options = new ScanOptions(HttpProtocol.HTTP_1, Duration.ofSeconds(1), 1, 1,
            Set.of(429, 503), 0, false, "conservative", "off", 1_000);
        var events = new ArrayList<ScanEvent>();
        var summary = new ScanEngine(options).run("idor", List.of(input),
            value -> new IdorPlanner().plan(value, new IdorPlanOptions("619", "620", "path:5",
                Set.of("idor.path.suffix_formats"), 1, false)),
            (value, timeout) -> new HttpResponseData(HttpProtocol.HTTP_1,
                value.rawTarget().equals("/v3/api/v3/namespaces/620/projects") ? 403 : 201,
                List.<HttpHeader>of(), new byte[0], 1), events::add);

        assertEquals(3, events.size());
        assertEquals("idor.baseline.control", events.get(0).planned().payload());
        assertEquals("idor.baseline.target", events.get(1).planned().payload());
        assertEquals("IDOR_CANDIDATE", events.get(2).signal());
        assertEquals(1, summary.findings());
    }

    @Test
    void redirectedTargetBaselineIsInconclusiveAndStopsMutations() throws Exception {
        HttpRequestData input = request();
        var events = new ArrayList<ScanEvent>();
        new ScanEngine(new ScanOptions(HttpProtocol.HTTP_1, Duration.ofSeconds(1), 1, 1,
            Set.of(429, 503), 0, false, "conservative", "off", 1_000)).run("idor", List.of(input),
            value -> new IdorPlanner().plan(value, new IdorPlanOptions("619", "620", "path:5",
                Set.of("idor.path.suffix_formats"), 1, false)),
            (value, timeout) -> new HttpResponseData(HttpProtocol.HTTP_1,
                value.rawTarget().equals("/v3/api/v3/namespaces/619/projects") ? 200 : 302,
                List.<HttpHeader>of(), new byte[0], 1), events::add);
        assertEquals(2, events.size());
        assertEquals("TARGET_BASELINE_INCONCLUSIVE", events.get(1).signal());
    }

    @Test
    void reducedPermissionsWithHttp200StillRunsQueryMutations() throws Exception {
        HttpRequestData input = new RawHttpRequestParser().parse((
            "GET /v3/bolt/user/permissions?include_nuance_permissions&project_id=7650 HTTP/2\r\n"
                + "Host: example.invalid\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1),
            TargetOrigin.parse("https://example.invalid"));
        IdorPlanOptions plan = new IdorPlanOptions("7650", "7648", "query:project_id#1",
            Set.of(), 1, false);
        ResponseGuidedIdorPlanner guided = new ResponseGuidedIdorPlanner();
        var events = new ArrayList<ScanEvent>();
        ScanEngine.Summary summary = new ScanEngine(new ScanOptions(HttpProtocol.HTTP_2,
            Duration.ofSeconds(1), 1, 1, Set.of(429, 503), 0, false,
            "conservative", "off", 1_000)).run("idor", List.of(input),
            request -> guided.initialPlan(request, plan),
            (request, authorized, target) -> guided.plan(request, plan, authorized, target),
            (request, timeout) -> {
                String permissions = request.rawTarget().contains("%0A")
                    || request.rawTarget().contains("project_id=7650")
                    ? "[\"read\",\"write\"]" : "[\"read\"]";
                return new HttpResponseData(HttpProtocol.HTTP_2, 200,
                    List.of(new HttpHeader("Content-Type", "application/json")),
                    ("{\"permissions\":" + permissions + "}").getBytes(StandardCharsets.UTF_8), 1);
            }, events::add);

        assertEquals(3, events.size());
        assertEquals("TARGET_BASELINE_2XX_REVIEW", events.get(1).signal());
        assertEquals("RESPONSE_CHANGED", events.get(2).signal());
        assertEquals(0, summary.findings());
        assertEquals(3, summary.requestsSent());
    }

    @Test
    void plainIdorPlannerAlsoContinuesAfterHttp200TargetBaseline() throws Exception {
        HttpRequestData input = new RawHttpRequestParser().parse((
            "GET /permissions?project_id=7650 HTTP/1.1\r\nHost: example.invalid\r\n\r\n")
            .getBytes(StandardCharsets.ISO_8859_1), TargetOrigin.parse("https://example.invalid"));
        var events = new ArrayList<ScanEvent>();
        ScanEngine.Summary summary = new ScanEngine(new ScanOptions(HttpProtocol.HTTP_1,
            Duration.ofSeconds(1), 1, 1, Set.of(429, 503), 0, false,
            "conservative", "off", 1_000)).run("idor", List.of(input),
            request -> new IdorPlanner().plan(request, new IdorPlanOptions("7650", "7648",
                "query:project_id#0", Set.of("idor.query.parameter_pollution"), 1, false)),
            (request, timeout) -> new HttpResponseData(HttpProtocol.HTTP_1, 200,
                List.of(), "{\"permissions\":[]}".getBytes(StandardCharsets.UTF_8), 1), events::add);

        assertEquals(3, events.size());
        assertEquals("TARGET_BASELINE_2XX_REVIEW", events.get(1).signal());
        assertEquals(0, summary.findings());
    }
}

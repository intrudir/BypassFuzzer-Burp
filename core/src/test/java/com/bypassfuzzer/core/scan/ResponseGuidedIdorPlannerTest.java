package com.bypassfuzzer.core.scan;

import com.bypassfuzzer.core.http.HttpHeader;
import com.bypassfuzzer.core.http.HttpProtocol;
import com.bypassfuzzer.core.http.HttpRequestData;
import com.bypassfuzzer.core.http.HttpResponseData;
import com.bypassfuzzer.core.http.RawHttpRequestParser;
import com.bypassfuzzer.core.http.RawHttpResponseParser;
import com.bypassfuzzer.core.http.TargetOrigin;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class ResponseGuidedIdorPlannerTest {
    private HttpRequestData request() {
        return new RawHttpRequestParser().parse(("POST /v2/orgs/alpha/assets HTTP/1.1\r\n"
            + "Host: example.invalid\r\nContent-Type: application/json\r\n\r\n"
            + "{\"name\":\"asset\"}").getBytes(StandardCharsets.UTF_8),
            TargetOrigin.parse("https://example.invalid"));
    }

    private HttpResponseData response(int status, String body) {
        return new HttpResponseData(HttpProtocol.HTTP_1, status,
            List.of(new HttpHeader("Content-Type", "application/json")),
            body.getBytes(StandardCharsets.UTF_8), 1);
    }

    private IdorPlanOptions options(int maximum) {
        return new IdorPlanOptions("alpha", "beta", "path:3",
            Set.of(ResponseGuidedIdorPlanner.FAMILY), maximum, false, null, "testrun");
    }

    @Test
    void discoversExactValuesAnywhereInJsonWithoutResourceSpecificKeys() {
        ResponseGuidedIdorPlanner planner = new ResponseGuidedIdorPlanner();
        var fields = planner.discover(response(201,
            "{\"tenantKey\":\"alpha\",\"members\":[{\"teams\":[{\"id\":\"alpha\"}]}],"
                + "\"url\":\"/alpha/assets\",\"assetId\":7651}"),
            response(403, "{\"requestedTenant\":\"beta\"}"), "alpha", "beta");
        assertEquals(List.of("/tenantKey", "/members/0/teams/0/id", "/requestedTenant"),
            fields.stream().map(ResponseGuidedIdorPlanner.ResponseField::pointer).toList());
        assertEquals(List.of("authorized", "authorized", "target"),
            fields.stream().map(ResponseGuidedIdorPlanner.ResponseField::baseline).toList());
    }

    @Test
    void preservesNumericIdentifiersAndParsesSavedHttp2Response() {
        HttpResponseData saved = new RawHttpResponseParser().parse(("HTTP/2 201 Created\r\n"
            + "Content-Type: application/json\r\n\r\n{\"departmentId\":41,\"note\":\"team-41\"}")
            .getBytes(StandardCharsets.ISO_8859_1));
        var planner = new ResponseGuidedIdorPlanner();
        var fields = planner.discover(saved, null, "41", "42");
        assertEquals(List.of("/departmentId"), fields.stream()
            .map(ResponseGuidedIdorPlanner.ResponseField::pointer).toList());
        assertTrue(fields.get(0).numeric());
        HttpRequestData numericRequest = new RawHttpRequestParser().parse(("POST /teams/41/members HTTP/1.1\r\n"
            + "Host: example.invalid\r\nContent-Type: application/json\r\n\r\n{\"name\":\"sample\"}")
            .getBytes(StandardCharsets.UTF_8), TargetOrigin.parse("https://example.invalid"));
        var plan = planner.plan(numericRequest, new IdorPlanOptions("41", "42", "path:2",
            Set.of(ResponseGuidedIdorPlanner.FAMILY), 2, false, null, "numeric"), saved, null);
        assertTrue(new String(plan.get(2).request().body(), StandardCharsets.UTF_8)
            .contains("\"departmentId\":42"));
        assertFalse(new String(plan.get(2).request().body(), StandardCharsets.UTF_8)
            .contains("\"departmentId\":\"42\""));
    }

    @Test
    void generatesBothDirectionsFromExactAndInferredShapesWithDistinctNames() {
        ResponseGuidedIdorPlanner planner = new ResponseGuidedIdorPlanner();
        List<PlannedRequest> plan = planner.plan(request(), options(40),
            response(201, "{\"tenantKey\":\"alpha\",\"members\":[{\"teams\":[{\"id\":\"alpha\"}]}]}"), null);
        assertEquals(2, plan.stream().filter(PlannedRequest::baseline).count());
        assertTrue(plan.stream().anyMatch(item -> item.intent() == ProbeIntent.MASS_ASSIGNMENT
            && item.request().rawTarget().equals("/v2/orgs/alpha/assets")
            && new String(item.request().body(), StandardCharsets.UTF_8).contains("\"tenantKey\":\"beta\"")));
        assertTrue(plan.stream().anyMatch(item -> item.intent() == ProbeIntent.PATH_BODY_CONFLICT
            && item.request().rawTarget().equals("/v2/orgs/beta/assets")
            && new String(item.request().body(), StandardCharsets.UTF_8).contains("\"tenantKey\":\"alpha\"")));
        assertTrue(plan.stream().anyMatch(item -> item.sourcePointer().equals("/members/0/teams/0/id")
            && new String(item.request().body(), StandardCharsets.UTF_8)
                .contains("\"members\":[{\"teams\":[{\"id\":\"beta\"}]}]")));
        assertTrue(plan.stream().anyMatch(item -> item.encoding().startsWith("alias ")));
        for (int index = 0; index < plan.size(); index++)
            assertTrue(new String(plan.get(index).request().body(), StandardCharsets.UTF_8)
                .contains("asset-bf-testrun-" + (index + 1)));
    }

    @Test
    void limitAndDisabledFamilyDoNotGenerateResponseProbes() {
        var planner = new ResponseGuidedIdorPlanner();
        var sample = response(201, "{\"tenantKey\":\"alpha\"}");
        assertEquals(3, planner.plan(request(), options(1), sample, null).size());
        var defaultFamilies = new IdorPlanOptions("alpha", "beta", "path:3",
            Set.of(), 2, false, null, "default");
        assertTrue(planner.enabled(defaultFamilies));
        assertTrue(planner.plan(request(), defaultFamilies, sample, null).stream()
            .anyMatch(item -> item.intent() == ProbeIntent.MASS_ASSIGNMENT));
        var disabled = new IdorPlanOptions("alpha", "beta", "path:3",
            Set.of("idor.path.suffix_formats"), 2, false);
        assertEquals(4, planner.plan(request(), disabled, sample, null).size());
        assertTrue(planner.plan(request(), disabled, sample, null).stream()
            .noneMatch(item -> item.intent() != ProbeIntent.STANDARD));
    }

    @Test
    void jsonSelectedLocationRemainsAtTargetValueWhenAddingConflictField() {
        HttpRequestData input = new RawHttpRequestParser().parse(("POST /assets HTTP/1.1\r\n"
            + "Host: example.invalid\r\nContent-Type: application/json\r\n\r\n"
            + "{\"name\":\"asset\",\"ownerId\":\"alpha\"}").getBytes(StandardCharsets.UTF_8),
            TargetOrigin.parse("https://example.invalid"));
        var options = new IdorPlanOptions("alpha", "beta", "json:/ownerId",
            Set.of(ResponseGuidedIdorPlanner.FAMILY), 2, false, null, "jsonslot");
        var plan = new ResponseGuidedIdorPlanner().plan(input, options,
            response(201, "{\"tenantKey\":\"alpha\"}"), null);
        String conflict = new String(plan.stream()
            .filter(item -> item.intent() == ProbeIntent.PATH_BODY_CONFLICT).findFirst().orElseThrow()
            .request().body(), StandardCharsets.UTF_8);
        assertTrue(conflict.contains("\"ownerId\":\"beta\""));
        assertTrue(conflict.contains("\"tenantKey\":\"alpha\""));
    }

    @Test
    void automaticUniqueFieldNeverChangesAnIdentifierValue() {
        HttpRequestData input = new RawHttpRequestParser().parse(("POST /accounts/alpha/items HTTP/1.1\r\n"
            + "Host: example.invalid\r\nContent-Type: application/json\r\n\r\n"
            + "{\"name\":\"alpha\"}").getBytes(StandardCharsets.UTF_8),
            TargetOrigin.parse("https://example.invalid"));
        var plan = new ResponseGuidedIdorPlanner().plan(input,
            new IdorPlanOptions("alpha", "beta", "path:2",
                Set.of(ResponseGuidedIdorPlanner.FAMILY), 2, false, null, "safe"),
            response(201, "{\"name\":\"alpha\"}"), null);
        assertEquals("{\"name\":\"alpha\"}",
            new String(plan.get(0).request().body(), StandardCharsets.UTF_8));
        assertTrue(plan.stream().anyMatch(item -> item.intent() == ProbeIntent.MASS_ASSIGNMENT
            && new String(item.request().body(), StandardCharsets.UTF_8).equals("{\"name\":\"beta\"}")));
    }

    @Test
    void engineClassifiesWriteAndTargetAccessSeparately() throws Exception {
        var planner = new ResponseGuidedIdorPlanner();
        var events = new ArrayList<ScanEvent>();
        ScanOptions scan = new ScanOptions(HttpProtocol.HTTP_1, Duration.ofSeconds(1), 1, 1,
            Set.of(429, 503), 0, false, "conservative", "off", 1_000);
        new ScanEngine(scan).run("idor", List.of(request()),
            value -> planner.initialPlan(value, options(2)),
            (value, authorized, target) -> planner.plan(value, options(2), authorized, target),
            (value, timeout) -> {
                String body = new String(value.body(), StandardCharsets.UTF_8);
                if (value.rawTarget().contains("/beta/") && !body.contains("\"tenantKey\""))
                    return response(403, "{\"error\":\"denied\"}");
                if (body.contains("\"tenantKey\":\"beta\""))
                    return response(201, "{\"tenantKey\":\"beta\"}");
                if (value.rawTarget().contains("/beta/"))
                    return response(201, "{\"tenantKey\":\"beta\"}");
                return response(201, "{\"tenantKey\":\"alpha\"}");
            }, events::add);
        assertEquals("MASS_ASSIGNMENT_CANDIDATE", events.get(2).signal());
        assertEquals("IDOR_CANDIDATE", events.get(3).signal());
        assertEquals(ProbeIntent.MASS_ASSIGNMENT, events.get(2).planned().intent());
        assertEquals(ProbeIntent.PATH_BODY_CONFLICT, events.get(3).planned().intent());
    }
}

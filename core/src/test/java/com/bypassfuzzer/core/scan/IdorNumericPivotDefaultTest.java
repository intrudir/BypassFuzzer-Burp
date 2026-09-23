package com.bypassfuzzer.core.scan;

import com.bypassfuzzer.core.http.RawHttpRequestParser;
import com.bypassfuzzer.core.http.TargetOrigin;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IdorNumericPivotDefaultTest {
    @Test
    void nearbyUnspecifiedIdsRequireExplicitFamilySelection() {
        var request = new RawHttpRequestParser().parse(
            "GET /projects/7651/stats?locale=en_US HTTP/1.1\r\nHost: example.invalid\r\n\r\n"
                .getBytes(StandardCharsets.ISO_8859_1), TargetOrigin.parse("https://example.invalid"));
        var planner = new IdorPlanner();
        assertTrue(planner.availableFamilies().contains(IdorPlanner.NUMERIC_PIVOTS_FAMILY));
        assertFalse(planner.defaultFamilies().contains(IdorPlanner.NUMERIC_PIVOTS_FAMILY));
        assertFalse(planner.defaultFamilies().contains(IdorPlanner.SPECIAL_IDENTIFIER_VALUES_FAMILY));
        assertFalse(planner.defaultFamilies().contains(IdorPlanner.JSON_EDGE_CASES_FAMILY));
        assertFalse(planner.defaultFamilies().contains(IdorPlanner.CANONICAL_IDENTIFIER_FORMATS_FAMILY));
        assertFalse(planner.defaultFamilies().contains(IdorPlanner.TRUNCATED_IDENTIFIER_VARIANTS_FAMILY));

        var defaultPlan = planner.plan(request,
            new IdorPlanOptions("7651", "7648", "path:2", Set.of(), 10_000, false));
        assertTrue(defaultPlan.stream().noneMatch(item ->
            item.family().equals(IdorPlanner.NUMERIC_PIVOTS_FAMILY)));
        assertTrue(defaultPlan.stream().noneMatch(item ->
            item.request().rawTarget().contains("/7649/")));
        for (String id : java.util.List.of("0", "1", "-1"))
            assertTrue(defaultPlan.stream().noneMatch(item ->
                item.request().rawTarget().contains("/projects/" + id + "/stats")));

        var explicitPlan = planner.plan(request,
            new IdorPlanOptions("7651", "7648", "path:2",
                Set.of(IdorPlanner.NUMERIC_PIVOTS_FAMILY), 10, false));
        assertEquals(5, explicitPlan.size());
        assertTrue(explicitPlan.stream().anyMatch(item ->
            item.request().rawTarget().equals("/projects/7649/stats?locale=en_US")));

        var specialPlan = planner.plan(request,
            new IdorPlanOptions("7651", "7648", "path:2",
                Set.of(IdorPlanner.SPECIAL_IDENTIFIER_VALUES_FAMILY), 10, false));
        for (String id : java.util.List.of("0", "1", "-1"))
            assertTrue(specialPlan.stream().anyMatch(item ->
                item.request().rawTarget().equals("/projects/" + id + "/stats?locale=en_US")));
    }

    @Test
    void jsonIdentifierEdgeValuesAreAlsoOptIn() {
        var request = new RawHttpRequestParser().parse(
            "POST /projects HTTP/1.1\r\nHost: example.invalid\r\nContent-Type: application/json\r\n\r\n"
                .concat("{\"projectId\":7651}").getBytes(StandardCharsets.ISO_8859_1),
            TargetOrigin.parse("https://example.invalid"));
        var planner = new IdorPlanner();
        var defaultPlan = planner.plan(request,
            new IdorPlanOptions("7651", "7648", "json:/projectId", Set.of(), 10_000, false));
        assertTrue(defaultPlan.stream().noneMatch(item ->
            item.family().equals(IdorPlanner.JSON_EDGE_CASES_FAMILY)));
        var explicitPlan = planner.plan(request,
            new IdorPlanOptions("7651", "7648", "json:/projectId",
                Set.of(IdorPlanner.JSON_EDGE_CASES_FAMILY), 10, false));
        for (String value : java.util.List.of("0", "-1", "1e0"))
            assertTrue(explicitPlan.stream().anyMatch(item ->
                new String(item.request().body(), StandardCharsets.UTF_8)
                    .contains("\"projectId\":" + value)));
    }

    @Test
    void shortenedAndCanonicalizedIdsCannotReintroduceOneByDefault() {
        var planner = new IdorPlanner();
        for (String target : java.util.List.of("1000", "0001")) {
            var request = new RawHttpRequestParser().parse(
                "GET /projects/7651/stats HTTP/1.1\r\nHost: example.invalid\r\n\r\n"
                    .getBytes(StandardCharsets.ISO_8859_1), TargetOrigin.parse("https://example.invalid"));
            var defaultPlan = planner.plan(request,
                new IdorPlanOptions("7651", target, "path:2", Set.of(), 10_000, false));
            assertTrue(defaultPlan.stream().noneMatch(item ->
                item.request().rawTarget().equals("/projects/1/stats")));
        }
    }
}

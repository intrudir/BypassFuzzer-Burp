package com.bypassfuzzer.core.scan;

import com.bypassfuzzer.core.http.HttpProtocol;
import com.bypassfuzzer.core.http.RawHttpRequestParser;
import com.bypassfuzzer.core.http.TargetOrigin;
import com.bypassfuzzer.core.urlvalidation.UrlValidationAttackSetting;
import com.bypassfuzzer.core.urlvalidation.UrlValidationContext;
import com.bypassfuzzer.core.urlvalidation.UrlValidationEncoding;
import com.bypassfuzzer.core.urlvalidation.UrlValidationOptions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SharedPlannerTest {
    @Test
    void allPayloadsIncludesEveryBypassFamilyAndNativeProtocolOverrides() {
        var request = request("POST /admin/users?id=7 HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nCookie: session=a\r\n\r\n{\"id\":7}");
        List<PlannedRequest> planned = new BypassPlanner().plan(request,
            new LinkedHashSet<>(Arrays.asList(AttackFamily.values())), false, 20_000);
        Set<String> families = planned.stream().map(PlannedRequest::family).collect(java.util.stream.Collectors.toSet());

        assertEquals(AttackFamily.values().length, families.size());
        assertTrue(planned.stream().anyMatch(item -> item.request().protocol() == HttpProtocol.HTTP_2));
        assertTrue(planned.stream().noneMatch(item -> item.payload().toLowerCase().contains("collaborator")));
    }

    @Test
    void idorEmitsBaselinesFirstAndEveryStablePlaybook() {
        List<PlannedRequest> planned = new IdorPlanner().plan(
            request("GET /users/100?id=100 HTTP/1.1\r\nHost: example.com\r\n\r\n"), "100", "200", 500);

        assertEquals("idor.baseline.control", planned.get(0).payload());
        assertEquals("idor.baseline.target", planned.get(1).payload());
        assertTrue(planned.subList(2, planned.size()).stream().map(PlannedRequest::family).distinct().count() >= 25);
    }

    @Test
    void urlValidationUsesMarkerAndHasNoCollaboratorSetting() {
        UrlValidationOptions options = new UrlValidationOptions("{INJECT}", "trusted.example", "127.0.0.1", "http",
            Set.of(UrlValidationContext.ABSOLUTE_URL), Set.of(UrlValidationAttackSetting.DOMAIN_ALLOW_LIST_BYPASS),
            Set.of(UrlValidationEncoding.RAW));
        List<PlannedRequest> planned = new UrlValidationPlanner().plan(
            request("GET /redirect?next={INJECT} HTTP/1.1\r\nHost: example.com\r\n\r\n"), options, 100);

        assertTrue(planned.size() > 1);
        assertFalse(planned.get(1).request().rawTarget().contains("{INJECT}"));
    }

    private com.bypassfuzzer.core.http.HttpRequestData request(String raw) {
        return new RawHttpRequestParser().parse(raw.getBytes(StandardCharsets.ISO_8859_1), TargetOrigin.parse("https://example.com"));
    }
}

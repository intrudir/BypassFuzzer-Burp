package com.bypassfuzzer.core.scan;

import com.bypassfuzzer.core.http.HttpProtocol;
import com.bypassfuzzer.core.http.HttpRequestData;
import com.bypassfuzzer.core.http.RawHttpRequestParser;
import com.bypassfuzzer.core.http.TargetOrigin;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class PairedControlSeparatorPlannerTest {
    private static final String FAMILY = PairedControlSeparatorPlanner.FAMILY;
    private final IdorPlanner planner = new IdorPlanner();

    @Test
    void defaultPathPreviewPrioritizesBothLfDirectionsAndNeverAddsThirdId() {
        HttpRequestData request = parse("GET /projects/7651/stats HTTP/1.1\r\nHost: example.invalid\r\n\r\n");
        var options = options("path:2", Set.of(), 50);
        var plan = planner.plan(request, options);
        assertEquals(FAMILY, plan.get(2).family());
        assertEquals("/projects/7651%0A7648/stats", plan.get(2).request().rawTarget());
        assertEquals("/projects/7648%0A7651/stats", plan.get(3).request().rawTarget());
        assertEquals("percent-encoded UTF-8", plan.get(2).encoding());
        assertTrue(plan.stream().noneMatch(item -> item.request().rawTarget().contains("/7649/")));
        assertEquals(10, plan.subList(2, 12).stream().filter(item -> item.family().equals(FAMILY)).count());
        var coverage = planner.separatorCoverage(request, options, plan);
        assertTrue(coverage.eligible() > coverage.planned());
        assertTrue(coverage.eligible() >= 170);
    }

    @Test
    void mutationLimitIsTotalAcrossSelectedPlaybooks() {
        HttpRequestData request = parse("GET /projects/7651/stats HTTP/1.1\r\n"
            + "Host: example.invalid\r\n\r\n");
        var plan = planner.plan(request, options("path:2",
            Set.of(FAMILY, "idor.path.suffix_formats"), 12));
        assertEquals(14, plan.size());
        assertEquals(2, plan.stream().filter(PlannedRequest::baseline).count());
        assertEquals(11, plan.stream().filter(item -> item.family().equals(FAMILY)).count());
        assertEquals(1, plan.stream().filter(item ->
            item.family().equals("idor.path.suffix_formats")).count());
    }

    @Test
    void unlimitedPlanIncludesEveryEligibleSeparatorAndLaterPlaybooks() {
        HttpRequestData request = parse("GET /projects/7651/stats HTTP/1.1\r\n"
            + "Host: example.invalid\r\n\r\n");
        var options = options("path:2", Set.of(), IdorPlanOptions.UNLIMITED);
        var plan = planner.plan(request, options);
        var coverage = planner.separatorCoverage(request, options, plan);
        assertTrue(plan.size() > 202);
        assertEquals(coverage.eligible(), coverage.planned());
        assertTrue(plan.stream().anyMatch(item -> item.family().equals("idor.path.suffix_formats")));
    }

    @Test
    void queryAndFormEncodeSeparatorOnce() {
        HttpRequestData query = parse("GET /items?id=7651 HTTP/1.1\r\nHost: example.invalid\r\n\r\n");
        var queryPlan = planner.plan(query, options("query:id#0", Set.of(FAMILY), 2));
        assertEquals("/items?id=7651%0A7648", queryPlan.get(2).request().rawTarget());
        assertEquals("7651\n7648", URLDecoder.decode(queryPlan.get(2).request().query().split("=", 2)[1],
            StandardCharsets.UTF_8));

        HttpRequestData form = parse("POST /items HTTP/1.1\r\nHost: example.invalid\r\n"
            + "Content-Type: application/x-www-form-urlencoded\r\n\r\nid=7651");
        var formPlan = planner.plan(form, options("form:id#0", Set.of(FAMILY), 2));
        assertEquals("id=7651%0A7648", body(formPlan.get(2).request()));
        assertEquals(String.valueOf(formPlan.get(2).request().body().length),
            formPlan.get(2).request().firstHeader("Content-Length").orElseThrow());
    }

    @Test
    void jsonUsesValidStringEscapesIncludingUnicodeControls() {
        HttpRequestData request = parse("POST /items HTTP/1.1\r\nHost: example.invalid\r\n"
            + "Content-Type: application/json\r\n\r\n{\"id\":7651,\"other\":\"keep\"}");
        var plan = planner.plan(request, options("json:/id", Set.of(FAMILY), 200));
        assertEquals("7651\n7648", JsonParser.parseString(body(plan.get(2).request()))
            .getAsJsonObject().get("id").getAsString());
        assertTrue(body(plan.get(2).request()).contains("\\n"));
        assertTrue(plan.stream().anyMatch(item -> item.family().equals(FAMILY)
            && JsonParser.parseString(body(item.request())).getAsJsonObject()
                .get("id").getAsString().contains("\u0080")));
        assertEquals("keep", JsonParser.parseString(body(plan.get(2).request()))
            .getAsJsonObject().get("other").getAsString());
    }

    @Test
    void headersAndCookiesHaveDistinctExactLocationsAndSafeCoverage() {
        HttpRequestData request = parse("GET /items HTTP/1.1\r\nHost: example.invalid\r\n"
            + "X-Object-Id: 7651\r\nX-Object-Id: 7651\r\n"
            + "X-Auth-Key: 7651\r\nCookie: auth_token=7651; sessionid=7651; project=7651\r\n\r\n");
        var locations = IdentifierLocation.discover(request, "7651");
        assertEquals(List.of("header:x-object-id#0", "header:x-object-id#1", "cookie:project#0"),
            locations.stream().map(IdentifierLocation::key).toList());
        assertEquals("7651", request.toRaw().substring(
            IdentifierLocationSpan.find(request, locations.get(0)).orElseThrow().start(),
            IdentifierLocationSpan.find(request, locations.get(0)).orElseThrow().end()));
        var headerPlan = planner.plan(request, options("header:x-object-id#1", Set.of(FAMILY), 10));
        assertEquals(4, headerPlan.size());
        assertEquals("7651", headerPlan.get(1).request().headers().get(1).value());
        assertEquals("7648", headerPlan.get(1).request().headers().get(2).value());
        assertTrue(headerPlan.get(2).request().headers().get(2).value().contains("\t"));
        assertFalse(headerPlan.get(2).request().headers().get(2).value().contains("\n"));
        assertEquals(2, planner.plan(request, options("cookie:project#0", Set.of(FAMILY), 10)).size());
        assertEquals("auth_token=7651; sessionid=7651; project=7648", planner.plan(request,
            options("cookie:project#0", Set.of(FAMILY), 10)).get(1).request()
            .firstHeader("Cookie").orElseThrow());
        HttpRequestData h2 = request.withProtocol(HttpProtocol.HTTP_2);
        assertEquals(2, planner.plan(h2, options("header:x-object-id#0", Set.of(FAMILY), 10)).size());
        HttpRequestData auto = request.withProtocol(HttpProtocol.AUTO);
        assertEquals(2, planner.plan(auto, options("header:x-object-id#0", Set.of(FAMILY), 10)).size());
    }

    @Test
    void textXmlAndMultipartPreserveOtherBodyContent() throws Exception {
        HttpRequestData text = parse("POST /items HTTP/1.1\r\nHost: example.invalid\r\n"
            + "Content-Type: text/plain\r\n\r\nproject=7651\nother=17651");
        assertEquals(List.of("text:#0"), IdentifierLocation.discover(text, "7651").stream()
            .map(IdentifierLocation::key).toList());
        var textPlan = planner.plan(text, options("text:#0", Set.of(FAMILY), 2));
        assertEquals("project=7651\n7648\nother=17651", body(textPlan.get(2).request()));

        HttpRequestData xml = parse("POST /items HTTP/1.1\r\nHost: example.invalid\r\n"
            + "Content-Type: application/xml\r\n\r\n<root id=\"7651\"><id>7651</id><keep>x</keep></root>");
        assertEquals(List.of("xml:attribute:id#0", "xml:text#0"),
            IdentifierLocation.discover(xml, "7651").stream().map(IdentifierLocation::key).toList());
        var xmlPlan = planner.plan(xml, options("xml:text#0", Set.of(FAMILY), 10));
        assertTrue(body(xmlPlan.get(2).request()).contains("7651&#xA;7648"));
        assertEquals("7651\n7648", DocumentBuilderFactory.newInstance().newDocumentBuilder()
            .parse(new ByteArrayInputStream(xmlPlan.get(2).request().body()))
            .getElementsByTagName("id").item(0).getTextContent());
        assertEquals("7651", DocumentBuilderFactory.newInstance().newDocumentBuilder()
            .parse(new ByteArrayInputStream(xmlPlan.get(2).request().body()))
            .getDocumentElement().getAttribute("id"));
        var xmlAttributePlan = planner.plan(xml, options("xml:attribute:id#0", Set.of(FAMILY), 2));
        assertEquals("7651\n7648", DocumentBuilderFactory.newInstance().newDocumentBuilder()
            .parse(new ByteArrayInputStream(xmlAttributePlan.get(2).request().body()))
            .getDocumentElement().getAttribute("id"));
        assertTrue(planner.separatorCoverage(xml, options("xml:text#0", Set.of(FAMILY), 10), xmlPlan)
            .notes().stream().anyMatch(note -> note.contains("XML")));

        String multipart = "--test\r\nContent-Disposition: form-data; name=\"project\"\r\n\r\n7651\r\n"
            + "--test\r\nContent-Disposition: form-data; name=\"file\"; filename=\"x.bin\"\r\n"
            + "Content-Type: application/octet-stream\r\n\r\n7651\u0000def\r\n--test--\r\n";
        HttpRequestData parts = parse("POST /items HTTP/1.1\r\nHost: example.invalid\r\n"
            + "Content-Type: multipart/form-data; boundary=test\r\n\r\n" + multipart);
        assertEquals(List.of("multipart:project#0"), IdentifierLocation.discover(parts, "7651")
            .stream().map(IdentifierLocation::key).toList());
        var partPlan = planner.plan(parts, options("multipart:project#0", Set.of(FAMILY), 2));
        assertTrue(body(partPlan.get(2).request()).contains("\r\n\r\n7651\n7648\r\n--test"));
        assertTrue(body(partPlan.get(2).request()).contains("7651\u0000def"));
        assertEquals(String.valueOf(partPlan.get(2).request().body().length),
            partPlan.get(2).request().firstHeader("Content-Length").orElseThrow());
    }

    private static IdorPlanOptions options(String location, Set<String> families, int limit) {
        return new IdorPlanOptions("7651", "7648", location, families, limit, false);
    }

    private static HttpRequestData parse(String raw) {
        return new RawHttpRequestParser().parse(raw.getBytes(StandardCharsets.ISO_8859_1),
            TargetOrigin.parse("https://example.invalid"));
    }

    private static String body(HttpRequestData request) {
        return new String(request.body(), StandardCharsets.UTF_8);
    }
}

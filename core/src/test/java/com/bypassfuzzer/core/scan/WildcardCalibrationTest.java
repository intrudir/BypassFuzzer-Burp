package com.bypassfuzzer.core.scan;

import com.bypassfuzzer.core.http.*;
import org.junit.jupiter.api.Test;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

class WildcardCalibrationTest {
    private HttpRequestData seed() { return new RawHttpRequestParser().parse("GET /api/v1/admin?tenant=42 HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer captured\r\nCookie: session=secret; preference=dark\r\nX-Keep: yes\r\n\r\n".getBytes(), TargetOrigin.parse("https://example.test")); }
    private HttpResponseData response(int status, int length) { return new HttpResponseData(HttpProtocol.HTTP_1, status, List.of(new HttpHeader("Content-Type","text/html; charset=UTF-8")), new byte[length], 0); }
    private ScanOptions options(boolean enabled,int retries) { return new ScanOptions(HttpProtocol.HTTP_1,Duration.ofSeconds(1),1,1,Set.of(429,503),retries,false,"ride-hard","off",1000,true,enabled); }
    @Test void siblingIsFreshAndPreservesSeedContext() {
        var a=WildcardCalibration.control(seed(),RequestAccess.CORE); var b=WildcardCalibration.control(seed(),RequestAccess.CORE);
        assertNotEquals(a.path(),b.path()); assertTrue(a.path().startsWith("/api/v1/__bf_control_")); assertEquals("tenant=42",a.query());
        assertEquals(seed().origin(),a.origin()); assertEquals(seed().headers(),a.headers()); assertArrayEquals(seed().body(),a.body());
    }
    @Test void comparisonUsesStatusMediaAndFiftyByteBoundary() {
        var a=new SweepClassifier.Response(200,100,"TEXT/HTML; charset=utf-8");
        assertEquals(WildcardCalibration.Assessment.MATCH,WildcardCalibration.compare("GET",a,new SweepClassifier.Response(200,150,"text/html"),Set.of(429)));
        assertEquals(WildcardCalibration.Assessment.DIFFERENT,WildcardCalibration.compare("GET",a,new SweepClassifier.Response(200,151,"text/html"),Set.of(429)));
        assertEquals(WildcardCalibration.Assessment.DIFFERENT,WildcardCalibration.compare("GET",a,new SweepClassifier.Response(201,100,"text/html"),Set.of(429)));
        assertEquals(WildcardCalibration.Assessment.DIFFERENT,WildcardCalibration.compare("GET",a,new SweepClassifier.Response(200,100,"application/json"),Set.of(429)));
    }
    @Test void headRequiresDeclaredLengthsAndThrottlingIsUnavailable() {
        var missing=new SweepClassifier.Response(200,0,"text/html");
        assertEquals(WildcardCalibration.Assessment.UNAVAILABLE,WildcardCalibration.compare("HEAD",missing,missing,Set.of(429)));
        var declared=new SweepClassifier.Response(200,0,"text/html",1000L);
        assertEquals(WildcardCalibration.Assessment.MATCH,WildcardCalibration.compare("HEAD",declared,new SweepClassifier.Response(200,0,"text/html",1049L),Set.of(429)));
        assertEquals(WildcardCalibration.Assessment.UNAVAILABLE,WildcardCalibration.compare("GET",new SweepClassifier.Response(429,0,""),missing,Set.of(429)));
        assertNull(WildcardCalibration.contentLength("bogus")); assertNull(WildcardCalibration.contentLength("-1"));
    }
    @Test void scanKeepsSignalAndOriginalAndCountsAllExchanges() throws Exception {
        var events=new ArrayList<ScanEvent>(); var sent=new ArrayList<HttpRequestData>();
        var summary=new ScanEngine(options(true,0)).run("bypass",List.of(seed()),b -> List.of(new PlannedRequest("Header","candidate","",b.upsertHeader("X-Probe","yes"),false)),(q,t) -> { sent.add(q); return response(q.path().contains("__bf_control_") || q.firstHeader("X-Probe").isPresent()?200:403,100); },events::add);
        assertEquals(3,summary.requestsSent()); assertEquals(3,events.size()); assertEquals(ControlRole.ORIGINAL,events.get(0).planned().controlRole());
        assertEquals(ControlRole.WILDCARD,events.get(1).planned().controlRole());
        var candidate=events.get(2); assertEquals("LIKELY_BYPASS",candidate.signal()); assertEquals(WildcardCalibration.Assessment.MATCH,candidate.calibration());
        assertEquals(1,summary.findings()); assertNotNull(candidate.fallbackResponse());
    }
    @Test void failedCalibrationRetriesButDoesNotAbortCandidate() throws Exception {
        var events=new ArrayList<ScanEvent>(); var attempts=new AtomicInteger();
        var summary=new ScanEngine(options(true,1)).run("bypass",List.of(seed()),b -> List.of(new PlannedRequest("Path","candidate","",b.withRawTarget("/other"),false)),(q,t) -> {
            if(q.path().contains("__bf_control_")) { attempts.incrementAndGet(); throw new java.io.IOException("owned fixture failure"); }
            return response(q.path().equals("/other")?200:403,100);
        },events::add);
        assertEquals(2,attempts.get()); assertEquals(4,summary.requestsSent()); assertEquals("LIKELY_BYPASS",events.get(3).signal());
        assertEquals(WildcardCalibration.Assessment.UNAVAILABLE,events.get(3).calibration());
        assertEquals(2,events.stream().filter(e -> e.planned().controlRole()==ControlRole.WILDCARD).count());
    }
    @Test void disabledAndNonGetScansEmitNoControls() throws Exception {
        for(var seed:List.of(seed(),seed().withMethod("POST"))) {
            var events=new ArrayList<ScanEvent>();
            new ScanEngine(options(seed.method().equals("POST"),0)).run("bypass",List.of(seed),b -> List.of(new PlannedRequest("Path","p","",b,false)),(q,t)->response(403,10),events::add);
            assertTrue(events.stream().noneMatch(e -> e.planned().controlRole()==ControlRole.WILDCARD));
        }
    }
    @Test void authenticatedSweepCalibratesOnlyStrippedContextAndRetainsHistory() {
        var workflow=new SweepWorkflow<HttpRequestData,HttpResponseData>(RequestAccess.CORE,SweepClassifier::response);
        var captured=response(200,300); var results=new ArrayList<SweepWorkflow.Result<HttpRequestData,HttpResponseData>>();
        var sent=new ArrayList<HttpRequestData>(); var counts=new AtomicInteger(); var policy=new RequestHeaderPolicy<>(RequestAccess.CORE,List.of(),UserAgentMode.DISABLED,0);
        var options=new SweepWorkflow.Options(true,true,false,Set.of("Authorization"),Set.of("session"),true,Set.of(429));
        workflow.execute(new SweepWorkflow.Candidate<>(seed(),captured,"owned",new SweepClassifier.Baseline(200,300,"text/html")),options,policy,
            () -> List.of(new SweepWorkflow.Probe<>("candidate","Header",workflow.stripAuthentication(seed(),options.authHeaders(),options.authCookies()).upsertHeader("X-Probe","yes"),HttpProtocol.HTTP_1,"bypass.header.forwarded",ControlRole.NONE)),
            p -> { sent.add(p.request()); return response(p.controlRole()==ControlRole.TARGET?403:200,100); },()->true,new SweepWorkflow.Observer<>() {
                public void planned(int n){counts.addAndGet(n);} public void completed(){counts.decrementAndGet();} public void skippedPublic(){fail();}
                public void result(SweepWorkflow.Result<HttpRequestData,HttpResponseData> value){results.add(value);}
            });
        assertEquals(0,counts.get()); assertEquals(3,sent.size());
        assertTrue(sent.stream().allMatch(q->q.firstHeader("Authorization").isEmpty() && q.firstHeader("Cookie").orElse("").equals("preference=dark")));
        var result=results.get(2); assertSame(captured,result.originalResponse()); assertEquals(WildcardCalibration.Assessment.MATCH,result.calibration());
        assertTrue(result.signal().startsWith(SweepClassifier.BYPASS_PREFIX)); assertNotNull(result.fallbackRequest());
    }
}

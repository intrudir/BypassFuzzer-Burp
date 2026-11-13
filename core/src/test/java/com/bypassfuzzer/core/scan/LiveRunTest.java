package com.bypassfuzzer.core.scan;

import com.bypassfuzzer.core.http.*;
import org.junit.jupiter.api.Test;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.time.Duration;
import static org.junit.jupiter.api.Assertions.*;

class LiveRunTest {
    private RunConfiguration config(Set<String> excluded,int concurrency,int perHost,double rate,Set<String> checks,String ua) {
        return new RunConfiguration(excluded,concurrency,perHost,rate,checks,List.of(new ConfiguredHeader("User-Agent",ua)),Set.of(),UserAgentMode.DISABLED,0);
    }
    private HttpRequestData seed(String host) {
        return new HttpRequestData(new TargetOrigin("http",host,80),"GET","/private",HttpProtocol.HTTP_1,List.of(new HttpHeader("Host",host)),new byte[0]);
    }
    private HttpResponseData response(int status) {return new HttpResponseData(HttpProtocol.HTTP_1,status,List.of(new HttpHeader("Content-Type","text/plain")),new byte[4],1);}
    private void paused(LiveRun run) throws Exception {
        long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);
        while(run.snapshot().state()!=LiveRun.State.PAUSED && System.nanoTime()<end)Thread.sleep(5);
        assertEquals(LiveRun.State.PAUSED,run.snapshot().state());
    }
    @Test void drainsBeforeAtomicApplyAndLeavesInvalidEditsPaused() throws Exception {
        var run=new LiveRun(config(Set.of(),2,2,400,Set.of("a"),"old"),Map.of("a","A"));
        var started=new CountDownLatch(1);var release=new CountDownLatch(1);
        var pool=Executors.newSingleThreadExecutor();
        try {
            var physical=pool.submit(() -> run.send(0,"api.test",() -> {started.countDown();release.await();return 200;}));
            assertTrue(started.await(3,TimeUnit.SECONDS));run.pause();
            assertEquals(LiveRun.State.PAUSING,run.snapshot().state());
            assertThrows(IllegalStateException.class,() -> run.apply(config(Set.of("api.test"),1,1,20,Set.of("a"),"new")));
            release.countDown();assertEquals(200,physical.get(3,TimeUnit.SECONDS));paused(run);
            assertThrows(IllegalArgumentException.class,() -> run.apply(config(Set.of(),1,1,20,Set.of("unknown"),"new")));
            assertEquals(0,run.snapshot().revision());assertEquals("old",run.snapshot().configuration().headers().get(0).value());
            run.apply(config(Set.of("API.TEST."),1,1,20,Set.of("a"),"new"));assertEquals(1,run.snapshot().headerRevision());
            assertEquals(LiveRun.State.PAUSED,run.snapshot().state());run.resume();
            assertThrows(LiveRun.Reconfigured.class,() -> run.send(0,"other.test",() -> 200));
            assertThrows(LiveRun.Excluded.class,() -> run.send(1,"api.test",() -> fail("excluded host reached network")));
        } finally {release.countDown();run.stop();pool.shutdownNow();}
    }
    @Test void replansPendingChecksAndHeadersWithoutRepeatingCompletedMutations() throws Exception {
        var run=new LiveRun(config(Set.of(),1,1,400,Set.of("a"),"old"),Map.of("a","A","b","B"));
        var options=new ScanOptions(HttpProtocol.HTTP_1,Duration.ofSeconds(2),1,1,Set.of(429),0,false,"ride-hard","off",1000,true,true);
        var engine=new ScanEngine(options,false,run);var wire=new CopyOnWriteArrayList<HttpRequestData>();var events=new CopyOnWriteArrayList<ScanEvent>();
        var pauseRequested=new CountDownLatch(1);var pool=Executors.newSingleThreadExecutor();
        try {
            var result=pool.submit(() -> engine.run("bypass",List.of(seed("first.test"),seed("second.test")),base -> {
                var probes=new ArrayList<PlannedRequest>();
                for(String check:List.of("a","b"))if(run.selected(check))for(int i=0;i<8;i++)probes.add(new PlannedRequest(check,check+i,"",base.withRawTarget("/"+check+i),false).withPlaybook(check));
                return probes;
            },(request,timeout) -> {
                wire.add(request);
                if(request.rawTarget().equals("/a0") && request.origin().host().equals("first.test")){run.pause();pauseRequested.countDown();}
                return response(request.rawTarget().equals("/private") ? 403 : 200);
            },events::add));
            assertTrue(pauseRequested.await(5,TimeUnit.SECONDS));paused(run);
            int boundary=wire.size();run.apply(config(Set.of("first.test"),2,1,50,Set.of("b"),"edited"));run.resume();
            var summary=result.get(10,TimeUnit.SECONDS);
            assertEquals("completed",summary.state());assertEquals(0,summary.transportErrors());
            assertEquals(1,wire.stream().filter(r -> r.origin().host().equals("first.test") && r.rawTarget().equals("/a0")).count());
            var after=wire.subList(boundary,wire.size());assertFalse(after.isEmpty());
            assertTrue(after.stream().allMatch(r -> r.origin().host().equals("second.test") && r.firstHeader("User-Agent").orElse("").equals("edited")));
            assertEquals(8,after.stream().filter(r -> r.rawTarget().startsWith("/b")).count());
            assertTrue(events.stream().noneMatch(e -> e.error()!=null));assertEquals(wire.size(),summary.requestsSent());
        }finally{run.stop();pool.shutdownNow();}
    }
    @Test void changingHeadersRefreshesControlsAndRetainsFinishedProbeHistory() throws Exception {
        var run=new LiveRun(config(Set.of(),1,1,400,Set.of("a"),"before"),Map.of("a","A","b","B"));
        var options=new ScanOptions(HttpProtocol.HTTP_1,Duration.ofSeconds(2),1,1,Set.of(429),0,false,"ride-hard","off",1000,true,true);
        var engine=new ScanEngine(options,false,run);var wire=new CopyOnWriteArrayList<HttpRequestData>();var events=new CopyOnWriteArrayList<ScanEvent>();var latch=new CountDownLatch(1);
        var pool=Executors.newSingleThreadExecutor();
        try {
            var result=pool.submit(() -> engine.run("bypass",List.of(seed("same.test")),base -> {
                var probes=new ArrayList<PlannedRequest>();for(String check:List.of("a","b"))if(run.selected(check))for(int i=0;i<4;i++)probes.add(new PlannedRequest(check,check+i,"",base.withRawTarget("/"+check+i),false).withPlaybook(check));return probes;
            },(request,timeout) -> {wire.add(request);if(request.rawTarget().equals("/a0")){run.pause();latch.countDown();}return response(request.rawTarget().equals("/private") ? 403 : 200);},events::add));
            assertTrue(latch.await(5,TimeUnit.SECONDS));paused(run);run.apply(config(Set.of(),1,1,400,Set.of("a","b"),"after"));run.resume();result.get(10,TimeUnit.SECONDS);
            assertEquals(1,wire.stream().filter(r -> r.rawTarget().equals("/a0")).count());
            assertEquals(2,events.stream().filter(e -> e.planned().controlRole()==ControlRole.ORIGINAL).count());
            assertEquals(2,events.stream().filter(e -> e.planned().controlRole()==ControlRole.WILDCARD).count());
            assertEquals(8,events.stream().filter(e -> e.planned().controlRole()==ControlRole.NONE).count());
            assertEquals(1,run.snapshot().headerRevision());
        }finally{run.stop();pool.shutdownNow();}
    }
    @Test void hardRateAndConcurrencyCapsApplyToPhysicalAttempts() throws Exception {
        var run=new LiveRun(config(Set.of(),1,1,10,Set.of(),"test"),Map.of());var times=new CopyOnWriteArrayList<Long>();
        var pool=Executors.newFixedThreadPool(3);var active=new AtomicInteger();var maximum=new AtomicInteger();
        try {var tasks=new ArrayList<Future<?>>();for(int i=0;i<3;i++)tasks.add(pool.submit(() -> run.send(0,"same.test",() -> {maximum.accumulateAndGet(active.incrementAndGet(),Math::max);times.add(System.nanoTime());Thread.sleep(15);active.decrementAndGet();return 200;})));for(var task:tasks)task.get(4,TimeUnit.SECONDS);
            assertEquals(1,maximum.get());for(int i=1;i<times.size();i++)assertTrue(times.get(i)-times.get(i-1)>=TimeUnit.MILLISECONDS.toNanos(90));
        }finally{run.stop();pool.shutdownNow();}
    }
    @Test void interruptedRetryCanaryRetainsEveryQueuedItem() {
        var queue=new ConcurrentLinkedQueue<>(List.of("one","two","three"));
        assertThrows(LiveRun.Reconfigured.class,() -> new DeferredRetryRunner<String>().run(queue,2,2,() -> true,s -> "host",s -> "family",s -> {throw new LiveRun.Reconfigured();},(s,a) -> fail("no retries before canary"),n -> {},s -> {}));
        assertEquals(Set.of("one","two","three"),Set.copyOf(queue));assertEquals(3,queue.size());
    }
    @Test void identicalTargetLabelsDoNotMergeDistinctSeeds() throws Exception {
        var run=new LiveRun(config(Set.of(),1,1,400,Set.of("a"),"ua"),Map.of("a","A"));
        var options=new ScanOptions(HttpProtocol.HTTP_1,Duration.ofSeconds(2),1,1,Set.of(429),0,false,"ride-hard","off",1000,false,false);
        var engine=new ScanEngine(options,false,run);var seen=new AtomicInteger();var records=new ArrayList<ScanEvent>();
        var first=seed("same.test").withBodyText("one");var second=seed("same.test").withBodyText("two");
        engine.run("bypass",List.of(first,second),base -> List.of(new PlannedRequest("a","same-label","",base,false)),(request,timeout) -> {seen.incrementAndGet();return response(200);},records::add);
        assertEquals(2,seen.get());assertEquals(2,records.size());
    }

    @Test void replanningKeepsCollaboratorPayloadIdentities() {
        var run=new LiveRun(config(Set.of(),1,1,400,Set.of(),"ua"),Map.of());var generated=new AtomicInteger();
        var first=run.domains("seed",() -> "payload"+generated.incrementAndGet());assertEquals("payload1",first.get());assertEquals("payload2",first.get());
        var replay=run.domains("seed",() -> "payload"+generated.incrementAndGet());assertEquals("payload1",replay.get());assertEquals("payload2",replay.get());assertEquals(2,generated.get());
    }

    @Test void removingTheMarkerHeaderIsRejectedBeforeApplyingAnEdit() {
        var base=seed("same.test").upsertHeader("X-Next","{INJECT}");
        var url=new com.bypassfuzzer.core.urlvalidation.UrlValidationOptions("{INJECT}","allowed.test","callback.test","http",null,null,null);
        var run=new LiveRun(config(Set.of(),1,1,20,Set.of(),"ua"),Map.of());
        run.validateUsing(c -> new UrlValidationPlanner().validate(c.prepare(base,RequestAccess.CORE),url));run.pause();
        var bad=new RunConfiguration(Set.of(),1,1,20,Set.of(),List.of(),Set.of("X-Next"),UserAgentMode.DISABLED,0);
        assertThrows(IllegalArgumentException.class,() -> run.apply(bad));assertEquals(0,run.snapshot().revision());assertEquals(LiveRun.State.PAUSED,run.snapshot().state());
    }

    @Test void exactSavedInventoryHonorsAnExplicitlyEmptySelection() throws Exception {
        var base=seed("saved.test");var probe=new PlannedRequest("Legacy pattern","saved request","",base,false);
        var catalog=RunPlans.savedCatalog(List.of(probe));
        var run=new LiveRun(config(Set.of(),1,1,400,Set.of(),"ua"),catalog);
        var options=new ScanOptions(HttpProtocol.HTTP_1,Duration.ofSeconds(1),1,1,Set.of(429),0,false,"ride-hard","off",1000,false,false);
        var result=new ScanEngine(options,false,run).run("sweep",List.of(base),request -> List.of(probe),(request,timeout) -> fail("disabled saved request reached network"),event -> fail("disabled saved request emitted evidence"));
        assertEquals(0,result.requestsSent());assertEquals(0,result.records());
    }

    @Test void identicalUrlsKeepSeparateOutOfBandIdentitiesForDifferentSeeds() throws Exception {
        var run=new LiveRun(config(Set.of(),1,1,400,Set.of("a"),"ua"),Map.of("a","A"));var generated=new AtomicInteger();var values=new ArrayList<String>();
        var options=new ScanOptions(HttpProtocol.HTTP_1,Duration.ofSeconds(1),1,1,Set.of(429),0,false,"ride-hard","off",1000,false,false);
        new ScanEngine(options,false,run).run("bypass",List.of(seed("same.test").withBodyText("first"),seed("same.test").withBodyText("second")),base -> {
            String domain=run.domains(base.targetLabel(),() -> "payload-"+generated.incrementAndGet()).get();
            return List.of(new PlannedRequest("a","probe","",base.upsertHeader("X-OOB",domain),false).withPlaybook("a"));
        },(request,timeout) -> {values.add(request.firstHeader("X-OOB").orElseThrow());return response(200);},event -> {});
        assertEquals(List.of("payload-1","payload-2"),values);
    }

    @Test void rejectsHeaderInjectionAndUsesExactHostExclusions() {
        assertThrows(IllegalArgumentException.class,() -> new RunConfiguration(Set.of(),1,1,20,Set.of(),List.of(new ConfiguredHeader("X-Test","ok\r\nInjected: bad")),Set.of(),UserAgentMode.DISABLED,0));
        assertThrows(IllegalArgumentException.class,() -> config(Set.of("https://api.test/"),1,1,20,Set.of(),"ua"));
        var c=config(Set.of("API.TEST."),1,1,20,Set.of(),"ua");assertTrue(c.excludes("api.test"));assertFalse(c.excludes("sub.api.test"));
    }
}

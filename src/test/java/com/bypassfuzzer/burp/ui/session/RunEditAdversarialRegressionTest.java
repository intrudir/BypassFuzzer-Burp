package com.bypassfuzzer.burp.ui.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.coverage.*;
import com.bypassfuzzer.burp.http.*;
import com.bypassfuzzer.cli.evidence.EvidenceWriter;
import com.bypassfuzzer.cli.run.*;
import com.bypassfuzzer.core.http.*;
import com.bypassfuzzer.core.scan.*;
import com.google.gson.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import static com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class RunEditAdversarialRegressionTest {
 @TempDir Path temporary;
 static RunConfiguration config(List<ConfiguredHeader> headers) {
  return new RunConfiguration(Set.of(),1,1,400,Set.of("a"),headers,Set.of(),UserAgentMode.DISABLED,0);
 }
 static HttpResponse nativeResponse(int status) {
  var response=mock(HttpResponse.class);var body=mock(ByteArray.class);
  when(body.length()).thenReturn(0);when(body.getBytes()).thenReturn(new byte[0]);
  when(response.body()).thenReturn(body);when(response.statusCode()).thenReturn((short)status);when(response.headers()).thenReturn(List.of());return response;
 }
 static HttpResponseData coreResponse(int status) {
  return new HttpResponseData(HttpProtocol.HTTP_1,status,List.of(),new byte[0],1);
 }
 static void paused(LiveRun live) throws Exception {
  long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);
  while(live.snapshot().state()!=LiveRun.State.PAUSED && System.nanoTime()<end)Thread.sleep(5);
  assertEquals(LiveRun.State.PAUSED,live.snapshot().state());
 }
 static AttackResult saved(HttpRequest base,HttpRequest mutation) {
  return new AttackResult("Bypass","probe","GET https://example.com/private","Path","",mutation,nativeResponse(429),base,nativeResponse(403));
 }
 @Test void replacingConfiguredHeaderListMustRemovePriorRunOnlyCredentialOnManualRetry() {
  var oldConfig=config(List.of(new ConfiguredHeader("Authorization","Bearer configured-only")));
  var live=new LiveRun(oldConfig,Map.of("a","A"));live.pause();live.apply(config(List.of()));live.resume();
  // The captured original seed had no Authorization; its retained control has the run-only configured credential.
  var original=oldConfig.prepare(request("/private","","GET",null,""),MontoyaRequestAccess.INSTANCE);
  var previous=saved(original,original.withPath("/mutation"));
  var contexts=new LiveRetryContext(live,Set.of(),Set.of(),Set.of(429),r -> {});
  var refreshed=contexts.prepare(previous,1,r -> nativeResponse(403));
  assertFalse(refreshed.getRequest().hasHeader("Authorization"),"A cleared run-only credential survives in the saved mutation");
  assertFalse(refreshed.getOriginalRequest().hasHeader("Authorization"));
 }
 @Test void manualRetryControlCacheMustSeparateCredentialsAtTheSameUrl() {
  var live=new LiveRun(config(List.of()),Map.of("a","A"));
  var contexts=new LiveRetryContext(live,Set.of(),Set.of(),Set.of(429),r -> {});var controls=new ArrayList<HttpRequest>();
  var first=requestWithHeaders("/private","","GET",Map.of("Authorization","Bearer tenant-A"),"");
  var second=requestWithHeaders("/private","","GET",Map.of("Authorization","Bearer tenant-B"),"");
  contexts.prepare(saved(first,first.withPath("/mutation")),0,r -> {controls.add(r);return nativeResponse(403);});
  var next=contexts.prepare(saved(second,second.withPath("/mutation")),0,r -> {controls.add(r);return nativeResponse(404);});
  assertEquals("Bearer tenant-B",next.getOriginalRequest().headerValue("Authorization"),"tenant-B retry is paired with tenant-A's control");
  assertEquals(2,controls.size());
 }
 @Test void nativeSweepMustNotMergeDistinctSeedsWithTheSameUrl() throws Exception {
  var api=mock(MontoyaApi.class,RETURNS_DEEP_STUBS);var wire=new CopyOnWriteArrayList<HttpRequest>();var results=new CopyOnWriteArrayList<AttackResult>();var done=new CountDownLatch(1);
  RequestSender sender=new RequestSender() {
   public HttpResponse send(HttpRequest r){wire.add(r);return nativeResponse(r.path().equals("/mutation") ? 200 : 403);}
   public HttpResponse send(HttpRequest r,long n,TimeUnit u){return send(r);}
  };
  var generator=new CoverageSweepProbeGenerator() {
   @Override public List<CoverageSweepProbe> buildProbes(HttpRequest r,CoverageSweepOptions o,boolean include) {
    return List.of(new CoverageSweepProbe("original","Control",r,null),new CoverageSweepProbe("mutation","Path",r.withPath("/mutation"),null));
   }
  };
  var baseline=new CoverageSweepOptions(Set.of(403),true,10,10,1,1,Set.of(429));
  var helper=Class.forName("com.bypassfuzzer.burp.core.coverage.CoverageSweepEngineTest").getDeclaredMethod("withoutCalibration",CoverageSweepOptions.class);helper.setAccessible(true);
  var options=(CoverageSweepOptions)helper.invoke(null,baseline);var candidates=new ArrayList<CoverageSweepCandidate>();
  for(String credential:List.of("tenant-A","tenant-B","tenant-A")) {
   var r=requestWithHeaders("/private","","GET",Map.of("Authorization",credential),"");
   candidates.add(new CoverageSweepCandidate(r,nativeResponse(403),credential,r.url(),"GET","example.com","/private",403,0,"",ZonedDateTime.now()));
  }
  var constructor=CoverageSweepEngine.class.getDeclaredConstructor(MontoyaApi.class,RequestSender.class,CoverageSweepProbeGenerator.class);constructor.setAccessible(true);var engine=constructor.newInstance(api,sender,generator);
  try {assertTrue(engine.start(candidates,options,results::add,done::countDown));assertTrue(done.await(8,TimeUnit.SECONDS));
   assertEquals(3,wire.stream().filter(r -> r.path().equals("/mutation")).count(),"second captured credential context is silently skipped");
  }finally{engine.cleanup();}
 }
 @Test void timedOutNativeSendMustRemainInFlightUntilPhysicalCallEnds() throws Exception {
  var api=mock(MontoyaApi.class,RETURNS_DEEP_STUBS);var physical=new AtomicInteger();var started=new CountDownLatch(1);var release=new CountDownLatch(1);
  var r=request("/private","","GET",null,"");var exchange=mock(HttpRequestResponse.class);var response=nativeResponse(200);when(exchange.response()).thenReturn(response);
  when(api.http().sendRequest(r,HttpMode.HTTP_1)).thenAnswer(inv -> {
   physical.incrementAndGet();started.countDown();try {while(release.getCount()>0)try{release.await();}catch(InterruptedException ignored){}return exchange;}finally{physical.decrementAndGet();}
  });
  var live=new LiveRun(config(List.of()),Map.of("a","A"));var pool=Executors.newSingleThreadExecutor();
  var sender=new MontoyaRequestSender(api,new com.bypassfuzzer.burp.core.throttle.GlobalTrafficGovernor());
  try {var sent=pool.submit(() -> sender.sendManaged(r,HttpMode.HTTP_1,100,TimeUnit.MILLISECONDS,() -> true,live,0));
   assertTrue(started.await(3,TimeUnit.SECONDS));assertNull(sent.get(3,TimeUnit.SECONDS));assertEquals(1,physical.get());
   live.pause();assertEquals(LiveRun.State.PAUSING,live.snapshot().state(),"drained state is reported while Montoya still owns a physical send");
  }finally{release.countDown();live.stop();pool.shutdownNow();}
 }
 @Test void successfulRetryAfterHeaderEditMustClearOriginalQueuedFailureInCli() throws Exception {
  var old=config(List.of(new ConfiguredHeader("User-Agent","before")));var live=new LiveRun(old,Map.of("a","A"));
  var origin=new TargetOrigin("http","fixture.test",80);var seed=new HttpRequestData(origin,"GET","/private",HttpProtocol.HTTP_1,List.of(new HttpHeader("Host","fixture.test")),new byte[0]);
  var options=new ExecutionOptions(temporary.resolve("evidence"),HttpProtocol.HTTP_1,Duration.ofSeconds(1),1,1,Set.of(429),false,1,"ride-hard","off",1000,false);
  var mutationCount=new AtomicInteger();var hit=new CountDownLatch(1);var pool=Executors.newSingleThreadExecutor();
  try(var evidence=new EvidenceWriter(options.outputDirectory(),"review",false,Map.of());var control=new RunControl(null,null,null,live)) {
   var job=pool.submit(() -> new ScanExecutor().run("bypass",List.of(seed),base -> List.of(new PlannedRequest("a","probe","",base.withRawTarget("/mutation"),false).withPlaybook("a")),null,
    control.transport((r,t) -> {if(!r.rawTarget().equals("/mutation"))return coreResponse(403);if(mutationCount.incrementAndGet()==1){live.pause();hit.countDown();return coreResponse(429);}return coreResponse(200);}),options,evidence,control));
   assertTrue(hit.await(5,TimeUnit.SECONDS));paused(live);live.apply(config(List.of(new ConfiguredHeader("User-Agent","after"))));live.resume();job.get(10,TimeUnit.SECONDS);
   var queue=JsonParser.parseString(Files.readString(options.outputDirectory().resolve("retry-queue.json"))).getAsJsonObject();
   assertEquals(0,queue.getAsJsonArray("entries").size(),"old raw-header key remains queued after successful retry under the new headers");
  }finally{live.stop();pool.shutdownNow();}
 }

 @Test void headerEditMustPreserveServerRetryAfterCooldown() throws Exception {
  var live=new LiveRun(config(List.of(new ConfiguredHeader("User-Agent","before"))),Map.of("a","A"));
  var seed=new HttpRequestData(new TargetOrigin("http","fixture.test",80),"GET","/private",HttpProtocol.HTTP_1,List.of(),new byte[0]);
  var options=new ScanOptions(HttpProtocol.HTTP_1,Duration.ofSeconds(1),1,1,Set.of(429),1,false,"ride-hard","off",1000,true,false);
  var engine=new ScanEngine(options,true,live);var hit=new CountDownLatch(1);var count=new AtomicInteger();var throttledAt=new AtomicLong();var afterEditAt=new AtomicLong();var pool=Executors.newSingleThreadExecutor();
  try {
   var job=pool.submit(() -> engine.run("bypass",List.of(seed),base -> List.of(new PlannedRequest("a","probe","",base.withRawTarget("/mutation"),false).withPlaybook("a")),(r,t) -> {
    if(r.firstHeader("User-Agent").orElse("").equals("after"))afterEditAt.compareAndSet(0,System.nanoTime());
    if(r.rawTarget().equals("/mutation") && count.incrementAndGet()==1) {
     throttledAt.set(System.nanoTime());live.pause();hit.countDown();return new HttpResponseData(HttpProtocol.HTTP_1,429,List.of(new HttpHeader("Retry-After","2")),new byte[0],1);
    }
    return coreResponse(r.rawTarget().equals("/private") ? 403 : 200);
   },event -> {}));
   assertTrue(hit.await(4,TimeUnit.SECONDS));paused(live);live.apply(config(List.of(new ConfiguredHeader("User-Agent","after"))));live.resume();job.get(8,TimeUnit.SECONDS);
   long elapsed=TimeUnit.NANOSECONDS.toMillis(afterEditAt.get()-throttledAt.get());assertTrue(elapsed>=1800,"server's two-second Retry-After was lost; next send after "+elapsed+"ms");
  }finally{live.stop();pool.shutdownNow();}
 }

 private AttackResult editedNativeDeferredRetry(HttpMode mode) throws Exception {
  var api=mock(MontoyaApi.class,RETURNS_DEEP_STUBS);var holder=new AtomicReference<CoverageSweepEngine>();var hit=new CountDownLatch(1);var done=new CountDownLatch(1);var sent=new AtomicInteger();var results=new CopyOnWriteArrayList<AttackResult>();
  RequestSender sender=new RequestSender() {
   public HttpResponse send(HttpRequest r) {
    if(r.path().equals("/mutation") && sent.incrementAndGet()==1){holder.get().pause();hit.countDown();return nativeResponse(429);}
    return nativeResponse(r.path().equals("/private") ? 403 : 200);
   }
   public HttpResponse send(HttpRequest r,long n,TimeUnit u){return send(r);}
   public HttpResponse send(HttpRequest r,HttpMode mode,long n,TimeUnit u){return send(r);}
  };
  var generator=new CoverageSweepProbeGenerator() {
   @Override public List<CoverageSweepProbe> buildProbes(HttpRequest r,CoverageSweepOptions o,boolean include) {
    return List.of(new CoverageSweepProbe("original","Control",r,null),new CoverageSweepProbe("mutation","Path",r.withPath("/mutation"),mode),new CoverageSweepProbe("next","Path",r.withPath("/next"),mode));
   }
  };
  var baseline=new CoverageSweepOptions(Set.of(403),true,10,10,1,1,Set.of(429));
  var helper=Class.forName("com.bypassfuzzer.burp.core.coverage.CoverageSweepEngineTest").getDeclaredMethod("withoutCalibration",CoverageSweepOptions.class);helper.setAccessible(true);var options=(CoverageSweepOptions)helper.invoke(null,baseline);
  var constructor=CoverageSweepEngine.class.getDeclaredConstructor(MontoyaApi.class,RequestSender.class,CoverageSweepProbeGenerator.class);constructor.setAccessible(true);var engine=constructor.newInstance(api,sender,generator);holder.set(engine);
  var r=requestWithHeaders("/private","","GET",Map.of("User-Agent","before","Authorization","Bearer before"),"");var candidate=new CoverageSweepCandidate(r,nativeResponse(403),"one",r.url(),"GET","example.com","/private",403,0,"",ZonedDateTime.now());
  try {assertTrue(engine.start(List.of(candidate),options,results::add,done::countDown));assertTrue(hit.await(5,TimeUnit.SECONDS));var live=engine.liveRun();paused(live);var c=live.snapshot().configuration();
   live.apply(new RunConfiguration(c.excludedHosts(),c.concurrency(),c.perHostConcurrency(),c.requestsPerSecond(),c.playbooks(),List.of(new ConfiguredHeader("User-Agent","after"),new ConfiguredHeader("Authorization","Bearer after")),c.removeHeaders(),UserAgentMode.DISABLED,0));engine.resume();assertTrue(done.await(8,TimeUnit.SECONDS));
   var retry=results.stream().filter(v -> v.getThrottleRetryAttempt()>0).findFirst().orElseThrow();System.out.println("mode="+mode+" retry-UA="+retry.getRequest().headerValue("User-Agent")+" revision="+retry.getEvidenceMetadata().configurationRevision());return retry;
  }finally{engine.cleanup();}
 }
 @Test void explicitRemoveStillStripsCredentialOnManualRetry() {
  var c=config(List.of());var next=new RunConfiguration(c.excludedHosts(),1,1,400,c.playbooks(),List.of(),Set.of("Authorization"),UserAgentMode.DISABLED,0);
  var live=new LiveRun(next,Map.of("a","A"));var base=requestWithHeaders("/private","","GET",Map.of("Authorization","Bearer old"),"");
  var refreshed=new LiveRetryContext(live,Set.of(),Set.of(),Set.of(429),r -> {}).prepare(saved(base,base.withPath("/mutation")),0,r -> nativeResponse(403));
  assertFalse(refreshed.getRequest().hasHeader("Authorization"));assertFalse(refreshed.getOriginalRequest().hasHeader("Authorization"));
 }
 @Test void excludedOriginCannotCrossFinalAdmissionAfterAnEdit() {
  var c=config(List.of());var live=new LiveRun(c,Map.of("a","A"));live.pause();live.apply(new RunConfiguration(Set.of("example.com"),1,1,400,c.playbooks(),List.of(),Set.of(),UserAgentMode.DISABLED,0));live.resume();
  assertThrows(LiveRun.Reconfigured.class,() -> live.send(0,"example.com",() -> fail("stale work was sent")));
  assertThrows(LiveRun.Excluded.class,() -> live.send(1,"example.com",() -> fail("excluded origin was sent")));
  assertEquals(0,live.snapshot().requestsSent());
 }
 @Test void lateQueuedResultMustRespectAlreadyAppliedHostExclusion() throws Exception {
  var helper=Class.forName("com.bypassfuzzer.burp.ui.session.SessionResultsWorkspaceTest").getDeclaredConstructor();helper.setAccessible(true);var test=helper.newInstance();
  var method=test.getClass().getDeclaredMethod("workspace",RequestSender.class);method.setAccessible(true);
  var workspace=(SessionResultsWorkspace)method.invoke(test,mock(RequestSender.class));
  var c=config(List.of());var live=new LiveRun(new RunConfiguration(Set.of("example.com"),1,1,400,c.playbooks(),List.of(),Set.of(),UserAgentMode.DISABLED,0),Map.of("a","A"));workspace.attachRunControl(() -> live);
  try {
   workspace.applyRunScope();
   // A response from the drained previous generation can reach the Swing queue after Apply & Resume.
   workspace.addResult(saved(request("/private","","GET",null,""),request("/mutation","","GET",null,"")));
   assertEquals(0,workspace.throttledRetryCount(),"an excluded host is reinserted by a late result");
  }finally{workspace.cleanup();}
 }

 @Test void automaticAutoProtocolSweepRetryMustUseEditedHeaders() throws Exception {
  var retry=editedNativeDeferredRetry(null);assertEquals("after",retry.getRequest().headerValue("User-Agent"),"AUTO retry misses refreshed memory template and sends stale headers");
 }
 @Test void refreshedHttp1SweepRetryMustRetainNewConfigurationRevision() throws Exception {
  var retry=editedNativeDeferredRetry(HttpMode.HTTP_1);assertEquals("after",retry.getRequest().headerValue("User-Agent"));
  assertEquals(1,retry.getEvidenceMetadata().configurationRevision(),"edited automatic Sweep retry is mislabeled as revision zero");
 }

 @Test void authenticatedCaptureCacheMustBeClearedBetweenSeparateEditedRuns() throws Exception {
  var api=mock(MontoyaApi.class,RETURNS_DEEP_STUBS);var holder=new AtomicReference<CoverageSweepEngine>();var hit=new AtomicReference<CountDownLatch>();var pauseOnce=new AtomicBoolean();var captures=new AtomicInteger();
  RequestSender sender=new RequestSender() {
   public HttpResponse send(HttpRequest r) {
    if(r.hasHeader("Authorization")){captures.incrementAndGet();return nativeResponse("Bearer round-2".equals(r.headerValue("Authorization")) ? 201 : 200);}
    if(r.path().equals("/private") && pauseOnce.compareAndSet(true,false)){holder.get().pause();hit.get().countDown();}
    return nativeResponse(r.path().equals("/private") ? 403 : 200);
   }
   public HttpResponse send(HttpRequest r,long n,TimeUnit u){return send(r);}
   public HttpResponse send(HttpRequest r,HttpMode mode,long n,TimeUnit u){return send(r);}
  };
  var generator=new CoverageSweepProbeGenerator() {
   @Override public List<CoverageSweepProbe> buildProbes(HttpRequest r,CoverageSweepOptions o,boolean include) {
    return List.of(new CoverageSweepProbe("mutation","Path",r.withPath("/mutation"),null));
   }
  };
  var d=CoverageSweepOptions.defaults();var initial=new CoverageSweepOptions(Set.of(),true,10,10,1,1,Set.of(429),CoverageSweepMode.AUTHENTICATED_TRAFFIC,new CoverageSweepAuthSelection(Set.of("Authorization"),Set.of(),false),true,true,false,List.of(),List.of(),CoverageSweepPayloadSet.HIGH_SIGNAL,d.posture(),d.familySelection(),d.pauseMode(),d.fixedPauseMillis(),UserAgentMode.DISABLED,0);
  var h=Class.forName("com.bypassfuzzer.burp.core.coverage.CoverageSweepEngineTest").getDeclaredMethod("withoutCalibration",CoverageSweepOptions.class);h.setAccessible(true);var options=(CoverageSweepOptions)h.invoke(null,initial);
  var ctor=CoverageSweepEngine.class.getDeclaredConstructor(MontoyaApi.class,RequestSender.class,CoverageSweepProbeGenerator.class);ctor.setAccessible(true);var engine=ctor.newInstance(api,sender,generator);holder.set(engine);
  var r=requestWithHeaders("/private","","GET",Map.of("Authorization","Bearer captured"),"");var candidate=new CoverageSweepCandidate(r,nativeResponse(200),"one",r.url(),"GET","example.com","/private",200,0,"",ZonedDateTime.now());
  try {
   for(int round=1;round<=2;round++) {
    hit.set(new CountDownLatch(1));pauseOnce.set(true);var done=new CountDownLatch(1);
    assertTrue(engine.start(List.of(candidate),options,result -> {},done::countDown));assertTrue(hit.get().await(5,TimeUnit.SECONDS));var live=engine.liveRun();paused(live);var c=live.snapshot().configuration();
    live.apply(new RunConfiguration(c.excludedHosts(),1,1,400,c.playbooks(),List.of(new ConfiguredHeader("Authorization","Bearer round-"+round)),Set.of(),UserAgentMode.DISABLED,0));engine.resume();assertTrue(done.await(8,TimeUnit.SECONDS));
   }
   assertEquals(2,captures.get(),"second edited run reuses the preceding run's authenticated response without sending its new credential");
  }finally{engine.cleanup();}
 }
}

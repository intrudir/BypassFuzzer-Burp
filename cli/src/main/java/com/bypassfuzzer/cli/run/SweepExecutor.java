package com.bypassfuzzer.cli.run;

import com.bypassfuzzer.cli.evidence.EvidenceWriter;
import com.bypassfuzzer.core.http.*;
import com.bypassfuzzer.core.scan.*;
import com.bypassfuzzer.core.throttle.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.Function;

/** Sweep's shared workflow, with generation-aware planning and retained completed work. */
public final class SweepExecutor {
    private record Retry(String seed,SweepWorkflow.Result<HttpRequestData,HttpResponseData> result,int attempt) { }
    private record Captured(HttpRequestData request,HttpResponseData response) { }
    public void run(List<HttpRequestData> inputs,Function<HttpRequestData,List<PlannedRequest>> planner,
        RequestTransport transport,ExecutionOptions execution,SweepWorkflow.Options options,
        RequestHeaderPolicy<HttpRequestData> initialPolicy,EvidenceWriter evidence,RunControl control) throws Exception {
        try(var archive=new ResponseArchive()) {
        Instant started=Instant.now();
        LiveRun live=control.liveRun();
        var settings=new ThrottleSettings(execution.throttleStatusCodes(),execution.globalConcurrency(),execution.perHostConcurrency(),400,
            ThrottleSettings.Posture.valueOf(execution.posture().replace('-','_').toUpperCase()),ThrottleSettings.PauseMode.valueOf(execution.pauseMode().toUpperCase()),execution.fixedPauseMillis());
        var throttle=new HostThrottleCoordinator<HttpRequestData,HttpResponseData>(settings,r -> r.origin().toString(),HttpResponseData::statusCode,r -> r.firstHeader("Retry-After").orElse(null),System.err::println);
        var workflow=new SweepWorkflow<HttpRequestData,HttpResponseData>(RequestAccess.CORE,SweepClassifier::response);
        inputs=CandidateScheduler.interleave(inputs,r -> r.origin().host());
        var queue=new ConcurrentLinkedQueue<Retry>();
        var memories=new ConcurrentHashMap<String,SweepWorkflow.Memory<HttpRequestData,HttpResponseData>>();
        var captures=new RunLedger<Captured>();
        var errors=new AtomicInteger();var findings=new AtomicInteger();var sent=new AtomicLong();
        var planned=new AtomicLong();var completed=new AtomicLong();var publicSkipped=new AtomicInteger();var quarantined=new AtomicInteger();
        var completedHosts=ConcurrentHashMap.<String>newKeySet();
        var generation=new AtomicLong();var headerGeneration=new AtomicLong();
        Function<SweepWorkflow.Probe<HttpRequestData>,HttpResponseData> send=probe -> {
            if(live!=null)live.checkpoint(generation.get());
            return throttle.send(probe.request(),() -> {
                try {
                    java.util.concurrent.Callable<HttpResponseData> physical=() -> {sent.incrementAndGet();return archive.retain(transport.sendManaged(probe.request().withProtocol(probe.protocol()),execution.requestTimeout(),live,generation.get()));};
                    return physical.call();
                } catch(LiveRun.Reconfigured | CancellationException error) {throw error;}
                catch(Exception error) {errors.incrementAndGet();return null;}
            },() -> {if(live!=null)live.checkpoint(generation.get());return control.continuing();});
        };
        try(var binding=control.bind(() -> {if(live==null)throttle.manualPause();},() -> {if(live==null)throttle.manualResume();},() -> {throttle.manualResume();})) {
          while(control.continuing()) {
            var snapshot=live==null ? null : live.snapshot();
            generation.set(snapshot==null ? 0 : snapshot.revision());headerGeneration.set(snapshot==null ? 0 : snapshot.headerRevision());
            planned.set(completed.get());
            evidence.recordConfiguration(live,generation.get());
            int concurrency=live==null ? execution.globalConcurrency() : live.snapshot().configuration().concurrency();
            if(live!=null)throttle.reconfigureConcurrency(concurrency,live.snapshot().configuration().perHostConcurrency());
            ExecutorService pool=Executors.newFixedThreadPool(concurrency);
            var tasks=new ArrayList<Future<?>>();
            for(int index=0;index<inputs.size();index++) {
              HttpRequestData original=inputs.get(index);int number=index;
              for(HttpProtocol protocol:execution.protocol()==HttpProtocol.BOTH ? List.of(HttpProtocol.HTTP_1,HttpProtocol.HTTP_2) : List.of(execution.protocol())) {
                String seed=number+"\n"+original.targetLabel()+"\n"+protocol;
                tasks.add(pool.submit(() -> {
                    if(!control.continuing())return;
                    evidence.configurationRevision(generation.get(),headerGeneration.get());
                    if(live!=null) {live.checkpoint(generation.get());if(!live.allowed(original.origin().host(),seed))return;}
                    if(live!=null)live.planningSeed(seed);
                    var config=live==null ? null : live.snapshot().configuration();
                    var policy=config==null ? initialPolicy : config.policy(RequestAccess.CORE);
                    var base=original.withProtocol(protocol);if(config!=null)base=config.prepare(base,RequestAccess.CORE);
                    final HttpRequestData candidateBase=base;
                    HttpResponseData captured=null;
                    if(options.authenticated()) {
                        String key=seed+"\n"+(headerGeneration.get());
                        var capture=captures.get(key,() -> {var request=policy.reconcileMutation(candidateBase,candidateBase);return new Captured(request,send.apply(new SweepWorkflow.Probe<>("Authenticated captured control","Control",request,protocol)));});
                        captured=capture.value().response();
                        if(capture.fresh()) write(evidence,PlannedRequest.baseline(capture.value().request(),"Authenticated captured control"),base.targetLabel(),captured,"BASELINE",0,WildcardCalibration.Assessment.DISABLED,null);
                    }
                    var candidate=new SweepWorkflow.Candidate<>(base,captured,base.targetLabel(),new SweepClassifier.Baseline(captured==null ? 0 : captured.statusCode(),captured==null ? 0 : captured.bodyLength(),captured==null ? "" : captured.firstHeader("Content-Type").orElse("")),protocol);
                    var memory=memories.computeIfAbsent(seed,ignored -> new SweepWorkflow.Memory<>());
                    memory.context(headerGeneration.get());
                    workflow.execute(candidate,options,policy,() -> {
                        var input=options.authenticated() ? workflow.stripAuthentication(candidateBase,options.authHeaders(),options.authCookies()) : candidateBase;
                        return planner.apply(input).stream().map(p -> new SweepWorkflow.Probe<>(p.payload(),p.family(),p.request(),p.request().protocol(),p.playbookId(),p.controlRole())).toList();
                    },send,control::continuing,new SweepWorkflow.Observer<HttpRequestData,HttpResponseData>() {
                        public void planned(int count){planned.addAndGet(count);}public void completed(){completed.incrementAndGet();}public void skippedPublic(){publicSkipped.incrementAndGet();}
                        public void result(SweepWorkflow.Result<HttpRequestData,HttpResponseData> r) {
                            emit(evidence,r,0);if(r.context().isFinding(r.probe().controlRole(),SweepClassifier.response(r.response())))findings.incrementAndGet();
                            if(r.probe().controlRole()!=ControlRole.TARGET && retryable(r.response(),execution))queue.add(new Retry(seed,r,0));
                        }
                    },memory);
                    completedHosts.add(original.origin().host());
                }));
              }
            }
            boolean changed=false;
            try {
                for(var task:tasks)try {task.get();}catch(ExecutionException error) {if(error.getCause() instanceof LiveRun.Reconfigured){changed=true;}else if(!(error.getCause() instanceof CancellationException) || !control.stopped())throw error;}
            } finally {pool.shutdownNow();while(!pool.awaitTermination(100,TimeUnit.MILLISECONDS)) { }}
            if(!control.continuing())break;
            if(changed || live!=null && live.snapshot().revision()!=generation.get())continue;
            queue.removeIf(r -> live!=null && (!live.allowed(r.result().probe().request().origin().host(),r.seed()) || !live.selected(RunPlans.checkId(planned(r.result())))));
            try {
                new DeferredRetryRunner<Retry>().run(queue,execution.retryAttempts(),concurrency,control::continuing,
                    r -> r.result().probe().request().origin().toString(),r -> r.result().probe().family(),r -> {
                        var current=memories.get(r.seed()).refresh(r.result());
                        var request=current.originalRequest()==null ? current.probe().request() : current.originalRequest();
                        var response=send.apply(new SweepWorkflow.Probe<>("Retry control canary","Control",request,request.protocol()));
                        return response!=null && !execution.throttleStatusCodes().contains(response.statusCode());
                    },(r,attempt) -> {
                        evidence.configurationRevision(generation.get(),headerGeneration.get());
                        var previous=memories.get(r.seed()).refresh(r.result());
                        var response=send.apply(previous.probe());var updated=workflow.retry(previous,response);emit(evidence,updated,attempt);
                        if(updated.context().isFinding(updated.probe().controlRole(),SweepClassifier.response(response)))findings.incrementAndGet();
                        boolean again=retryable(response,execution);if(again)queue.add(new Retry(r.seed(),updated,attempt));return again;
                    },quarantined::addAndGet,System.err::println);
            }catch(LiveRun.Reconfigured changedDuringRetry) {continue;}
            if(live==null || live.snapshot().revision()==generation.get())break;
          }
        }
        evidence.retryPackage(queue.stream().map(r -> evidence.retryEntry(planned(r.result()),r.attempt())).toList());
        var summary=new LinkedHashMap<String,Object>();summary.put("schemaVersion",1);summary.put("mode","sweep");summary.put("state",control.stopped() ? "stopped" : "completed");
        summary.put("startedAt",started.toString());summary.put("finishedAt",Instant.now().toString());summary.put("inputs",inputs.size());summary.put("records",evidence.count());summary.put("requestsSent",live==null ? sent.get() : live.snapshot().requestsSent());
        summary.put("findings",findings.get());summary.put("transportErrors",errors.get());summary.put("plannedRequests",planned.get());summary.put("completedRequests",completed.get());summary.put("skippedPublicEndpoints",publicSkipped.get());
        summary.put("deferredRetries",queue.size());summary.put("quarantinedRetries",quarantined.get());summary.put("completedHosts",completedHosts.stream().filter(host -> live==null || !live.snapshot().configuration().excludes(host)).sorted().toList());
        if(live!=null){summary.put("configurationRevision",live.snapshot().revision());summary.put("skippedTargets",live.snapshot().skipped());}
        evidence.recordConfigurations(live);
        evidence.summary(summary);
        }
    }
    private static PlannedRequest planned(SweepWorkflow.Result<HttpRequestData,HttpResponseData> r) {
        return new PlannedRequest(r.probe().family(),r.probe().label(),"",r.probe().request(),r.probe().controlRole()!=ControlRole.NONE,ProbeIntent.STANDARD,"","",r.probe().playbookId(),r.probe().controlRole());
    }
    private static void emit(EvidenceWriter evidence,SweepWorkflow.Result<HttpRequestData,HttpResponseData> r,int attempt){write(evidence,planned(r),r.target(),r.response(),r.signal(),attempt,r.calibration(),r.fallbackRequest());}
    private static void write(EvidenceWriter evidence,PlannedRequest p,String target,HttpResponseData response,String signal,int attempt,WildcardCalibration.Assessment calibration,HttpRequestData fallback) {
        try {evidence.write("sweep",target,p,response,null,signal,attempt,calibration,fallback);}catch(java.io.IOException error){throw new java.io.UncheckedIOException(error);}
    }
    private static boolean retryable(HttpResponseData response,ExecutionOptions options){return response==null || options.throttleStatusCodes().contains(response.statusCode());}
}

package com.bypassfuzzer.cli.run;

import com.bypassfuzzer.core.http.*;
import com.bypassfuzzer.core.scan.*;
import com.bypassfuzzer.core.throttle.GlobalTrafficGovernor;
import com.google.gson.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import java.util.concurrent.*;

/** Plain pause/resume/stop commands and atomic JSON edits, with a credential-free status readback. */
public final class RunControl implements AutoCloseable {
    private record Binding(Runnable pause, Runnable resume, Runnable stop) { }
    private final List<Binding> bindings = new CopyOnWriteArrayList<>();
    private final GlobalTrafficGovernor<HttpRequestData> governor = new GlobalTrafficGovernor<>(r -> r.origin().toString());
    private final ScheduledExecutorService watcher;
    private final LiveRun live;
    private String lastContent, lastError="", lastId="";
    private volatile String state = "resume";

    public RunControl(Path file, Integer maxInFlight, Double maxRate) { this(file,maxInFlight,maxRate,null); }
    public RunControl(Path file, Integer maxInFlight, Double maxRate, LiveRun live) {
        this.live=live;
        if (maxInFlight != null && maxInFlight < 1 || maxRate != null && (!Double.isFinite(maxRate) || maxRate <= 0))
            throw new IllegalArgumentException("Traffic limits must be positive");
        governor.configure(maxInFlight != null || maxRate != null,maxInFlight == null ? 10 : maxInFlight,maxRate == null ? 10 : maxRate);
        if (file == null) watcher=null;
        else {
            if(!Files.isDirectory(file.toAbsolutePath().getParent()) || Files.isDirectory(file))throw new IllegalArgumentException("Control file requires an existing parent directory and a file path");
            try{status(file);}catch(java.io.IOException error){throw new IllegalArgumentException("Unable to create the control status file",error);}
            watcher=Executors.newSingleThreadScheduledExecutor(r -> { var t=new Thread(r,"bypassfuzzer-run-control"); t.setDaemon(true);return t; });
            poll(file);
            watcher.scheduleWithFixedDelay(() -> poll(file),100,100,TimeUnit.MILLISECONDS);
        }
    }
    public LiveRun liveRun() { return live; }
    public AutoCloseable bind(Runnable pause, Runnable resume, Runnable stop) {
        var binding=new Binding(pause,resume,stop);bindings.add(binding);apply(binding,state);
        return () -> bindings.remove(binding);
    }
    public boolean continuing() { return !state.equals("stop") && !Thread.currentThread().isInterrupted(); }
    public boolean stopped() { return state.equals("stop"); }
    public RequestTransport transport(RequestTransport network) {
        return new RequestTransport() {
            public HttpResponseData send(HttpRequestData request,java.time.Duration timeout) throws Exception {return sendManaged(request,timeout,null,0);}
            public HttpResponseData sendManaged(HttpRequestData request,java.time.Duration timeout,LiveRun run,long revision) throws Exception {
                try {
                    return governor.execute(request,() -> {
                        try{return network.send(request,timeout);}
                        catch(Exception error){throw new CompletionException(error);}
                    },() -> {if(run!=null)run.checkpoint(revision);return continuing();},run==null ? null : run.admission(revision,request.origin().host()));
                }catch(CompletionException error){if(error.getCause() instanceof Exception cause)throw cause;throw error;}
            }
        };
    }
    private synchronized void poll(Path file) {
        try {
            if(!stopped() && Files.isRegularFile(file)) {
                String content=Files.readString(file).trim();
                if(!content.equals(lastContent)) {
                    lastContent=content;
                    try { command(content);lastError=""; }
                    catch (RuntimeException error) { lastError=error.getMessage()==null ? error.getClass().getSimpleName() : error.getMessage(); System.err.println("Run edit rejected; configuration unchanged: "+lastError); }
                }
            }
            status(file);
        } catch (java.io.IOException error) { System.err.println("Unable to read/write run control: "+error.getMessage()); }
    }
    private void command(String content) {
        if(content.isEmpty())return;
        if(!content.startsWith("{")) { transition(content.toLowerCase(Locale.ROOT));return; }
        if(live==null) throw new IllegalArgumentException("This run does not support configuration edits");
        JsonObject json=JsonParser.parseString(content).getAsJsonObject();
        unknown(json,Set.of("action","expectedRevision","commandId","configuration"));
        String action=string(json.get("action"));
        String commandId=json.has("commandId") ? string(json.get("commandId")) : "";
        if(!Set.of("pause","resume","stop","apply","apply-resume").contains(action)) throw new IllegalArgumentException("Unknown control action");
        if(action.equals("apply") || action.equals("apply-resume")) {
            long expected=json.get("expectedRevision").getAsBigDecimal().longValueExact();
            if(expected!=live.snapshot().revision()) throw new IllegalArgumentException("Configuration revision changed; read the status file and retry");
            var previous=live.snapshot().configuration();
            var next=patch(previous,json.getAsJsonObject("configuration"));
            live.apply(next);
            if(next.playbooks()!=null)for(var risk:new IdorPlanner().dangerousFamilyRisks().entrySet())
                if(next.playbooks().contains(risk.getKey()) && (previous.playbooks()==null || !previous.playbooks().contains(risk.getKey())))System.err.println("DANGEROUS: "+risk.getKey()+": "+risk.getValue());
            if(action.equals("apply-resume")) transition("resume");
        } else {
            if(json.has("configuration")) throw new IllegalArgumentException("Configuration edits require apply or apply-resume");
            transition(action);
        }
        lastId=commandId;
    }
    private static void unknown(JsonObject object,Set<String> allowed) {
        if(object==null || !allowed.containsAll(object.keySet())) throw new IllegalArgumentException("Unknown run-control key");
    }
    public static RunConfiguration patch(RunConfiguration old,JsonObject json) {
        unknown(json,Set.of("excludeHosts","concurrency","perHostConcurrency","requestsPerSecond","playbooks","headers","removeHeaders","userAgentMode","userAgentSeed"));
        List<ConfiguredHeader> headers=old.headers();
        if(json.has("headers")) {
            var lines=strings(json,"headers");
            if(lines.stream().anyMatch(line -> line.indexOf('\r')>=0 || line.indexOf('\n')>=0))throw new IllegalArgumentException("Each headers entry must contain one header line");
            headers=ConfiguredHeaderParser.parse(String.join("\n",lines));
        }
        return new RunConfiguration(json.has("excludeHosts") ? new LinkedHashSet<>(strings(json,"excludeHosts")) : old.excludedHosts(),
            json.has("concurrency") ? json.get("concurrency").getAsBigDecimal().intValueExact() : old.concurrency(),
            json.has("perHostConcurrency") ? json.get("perHostConcurrency").getAsBigDecimal().intValueExact() : old.perHostConcurrency(),
            json.has("requestsPerSecond") ? json.get("requestsPerSecond").getAsDouble() : old.requestsPerSecond(),
            json.has("playbooks") ? new LinkedHashSet<>(strings(json,"playbooks")) : old.playbooks(),headers,
            json.has("removeHeaders") ? new LinkedHashSet<>(strings(json,"removeHeaders")) : old.removeHeaders(),
            json.has("userAgentMode") ? UserAgentMode.valueOf(json.get("userAgentMode").getAsString().replace('-','_').toUpperCase(Locale.ROOT)) : old.userAgentMode(),
            json.has("userAgentSeed") ? json.get("userAgentSeed").getAsBigDecimal().longValueExact() : old.userAgentSeed());
    }
    private static String string(JsonElement value) {
        if(value==null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString())throw new IllegalArgumentException("Control actions, command IDs and list entries must be strings");
        return value.getAsString();
    }
    private static List<String> strings(JsonObject object,String name) {
        var result=new ArrayList<String>();for(var value:object.getAsJsonArray(name))result.add(string(value));return result;
    }
    private void transition(String command) {
        if(!Set.of("pause","resume","stop").contains(command)) throw new IllegalArgumentException("Control must be pause, resume, stop, or a JSON edit");
        if(command.equals(state))return;
        state=command;
        if(live!=null) { if(command.equals("pause")) live.pause();else if(command.equals("resume"))live.resume();else live.stop(); }
        if(live==null && command.equals("pause"))governor.pause();else governor.resume();
        for(var binding:bindings)apply(binding,command);
    }
    private void status(Path file) throws java.io.IOException {
        var data=new LinkedHashMap<String,Object>();
        data.put("state",state);data.put("lastCommandId",lastId);data.put("error",lastError);
        if(live!=null) {
            var snapshot=live.snapshot();var c=snapshot.configuration();
            data.put("state",snapshot.state().name().toLowerCase(Locale.ROOT));data.put("revision",snapshot.revision());
            data.put("headerRevision",snapshot.headerRevision());data.put("inFlight",snapshot.inFlight());
            data.put("requestsSent",snapshot.requestsSent());data.put("skipped",snapshot.skipped());
            data.put("hosts",live.hosts().stream().sorted().toList());data.put("availablePlaybooks",live.availablePlaybooks());
            data.put("configuration",Map.of("excludeHosts",c.excludedHosts(),"concurrency",c.concurrency(),"perHostConcurrency",c.perHostConcurrency(),
                "requestsPerSecond",c.requestsPerSecond(),"playbooks",c.playbooks()==null ? List.of() : c.playbooks(),
                "headerNames",c.headers().stream().map(ConfiguredHeader::name).toList(),"removeHeaders",c.removeHeaders(),"userAgentMode",c.userAgentMode().name()));
        }
        Path output=file.resolveSibling(file.getFileName()+".status.json").toAbsolutePath();
        Path tmp=Files.createTempFile(output.getParent(),".bypassfuzzer-status-",".tmp");
        try {
            try { Files.setPosixFilePermissions(tmp,PosixFilePermissions.fromString("rw-------")); }catch(UnsupportedOperationException ignored) { }
            Files.writeString(tmp,new Gson().toJson(data));
            Files.move(tmp,output,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
        } finally {Files.deleteIfExists(tmp);}
    }
    private void apply(Binding b,String command) { switch(command) {case "pause" -> b.pause().run();case "resume" -> b.resume().run();case "stop" -> b.stop().run();} }
    @Override public void close() {
        if(watcher==null)return;
        watcher.shutdownNow();
        try{watcher.awaitTermination(2,TimeUnit.SECONDS);}catch(InterruptedException error){Thread.currentThread().interrupt();}
    }
}

package com.bypassfuzzer.core.scan;

import java.util.*;
import java.util.concurrent.Callable;
import java.util.function.Supplier;

/** One atomic pause/edit/resume boundary, shared by every mode and both hosts. */
public final class LiveRun {
    public enum State { RUNNING, PAUSING, PAUSED, STOPPED }
    public record Snapshot(long revision, long headerRevision, State state, int inFlight,
                           long requestsSent, long skipped, RunConfiguration configuration) { }
    public static final class Reconfigured extends RuntimeException { }
    public static final class Excluded extends RuntimeException {
        public Excluded(String host) { super("Skipped: host excluded: " + host); }
    }
    private RunConfiguration configuration;
    private java.util.function.Consumer<RunConfiguration> configurationValidator=ignored -> {};
    private final Map<Long,RunConfiguration> history=new HashMap<>();
    private final Map<Long,Long> headerHistory=new HashMap<>();
    private long revision, headerRevision, sent;
    private boolean paused, stopped;
    private int active;
    private final Map<String,Integer> activeByHost = new HashMap<>();
    private final Map<String,Long> lastSend = new HashMap<>();
    private final Set<String> skipped = new HashSet<>();
    private final Map<String,String> available;
    private final Set<String> hosts = new java.util.concurrent.ConcurrentSkipListSet<>();
    private final ThreadLocal<String> planningSeed=new ThreadLocal<>();
    private final Map<String,String> outOfBand=new java.util.concurrent.ConcurrentHashMap<>();
    private final Map<String,Object> controlRequests = new java.util.concurrent.ConcurrentHashMap<>();

    public LiveRun(RunConfiguration initial, Map<String,String> available) {
        this.available = Collections.unmodifiableMap(new LinkedHashMap<>(available));
        validate(initial); configuration = initial;history.put(0L,initial);headerHistory.put(0L,0L);
    }
    private void validate(RunConfiguration value) {
        if (value.playbooks() != null && !available.keySet().containsAll(value.playbooks()))
            throw new IllegalArgumentException("Unknown or unavailable playbook in run configuration");
    }
    public synchronized long headerRevision(long revision){return headerHistory.getOrDefault(revision,0L);}
    public synchronized RunConfiguration configuration(long revision){return history.get(revision);}
    public synchronized void validateUsing(java.util.function.Consumer<RunConfiguration> validator){configurationValidator=validator;}
    public Map<String,String> availablePlaybooks() { return available; }
    public void registerHost(String host) { hosts.add(RunConfiguration.normalizeHost(host)); }
    public Set<String> hosts() { return Set.copyOf(hosts); }
    public synchronized Snapshot snapshot() {
        return new Snapshot(revision, headerRevision, stopped ? State.STOPPED : !paused ? State.RUNNING : active == 0 ? State.PAUSED : State.PAUSING,
            active, sent, skipped.size(), configuration);
    }
    public synchronized void pause() { if (!stopped) paused = true; notifyAll(); }
    public synchronized void resume() { if (!stopped) paused = false; notifyAll(); }
    public synchronized void stop() { stopped = true; paused = false; notifyAll(); }
    /** Invalid edits leave both the previous configuration and pause state intact. */
    public synchronized void apply(RunConfiguration next) {
        if (!paused || active != 0 || stopped) throw new IllegalStateException("Wait until the run is fully paused before applying changes");
        validate(next);configurationValidator.accept(next);
        if (configuration.equals(next)) return;
        if (!configuration.sameHeaders(next)) headerRevision++;
        configuration = next; revision++;history.put(revision,next);headerHistory.put(revision,headerRevision); notifyAll();
    }
    public synchronized void checkpoint(long expectedRevision) {
        while (paused && !stopped && !Thread.currentThread().isInterrupted()) {
            try { wait(100); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }
        if (stopped || Thread.currentThread().isInterrupted()) throw new java.util.concurrent.CancellationException("Run stopped");
        if (expectedRevision != revision) throw new Reconfigured();
    }
    public synchronized boolean allowed(String host, String workKey) {
        registerHost(host);
        if (!configuration.excludes(host)) return true;
        skipped.add(workKey); return false;
    }
    public synchronized boolean selected(String id) {
        return id == null || id.isEmpty() || configuration.playbooks() == null || configuration.playbooks().contains(id);
    }
    public synchronized boolean selected(PlannedRequest probe){return selected(probe.playbookId(),probe.family(),probe.controlRole());}
    public synchronized boolean selected(String playbook,String family,ControlRole role) {
        if(role!=ControlRole.NONE)return true;
        String id=RunPlans.savedId(family,playbook);
        if(available.containsKey(id))return selected(id);
        if(playbook!=null && !playbook.isEmpty())return selected(playbook);
        if(available.containsKey(family))return selected(family);
        String highSignal=BypassPlaybooks.highSignalId(family==null ? "" : family);
        if(available.containsKey(highSignal))return selected(highSignal);
        for(var attack:AttackFamily.values())if(attack.displayName().equalsIgnoreCase(family==null ? "" : family) && available.containsKey("bypass."+attack.id()+".base"))return selected("bypass."+attack.id()+".base");
        return configuration.playbooks()==null || !configuration.playbooks().isEmpty();
    }
    /** Reservations never wait while a shared governor holds its lock or permits. */
    private synchronized long tryAcquire(long expectedRevision,String host) {
        if(stopped || Thread.currentThread().isInterrupted())throw new java.util.concurrent.CancellationException("Run stopped");
        if(expectedRevision!=revision)throw new Reconfigured();
        if(paused)return Long.MAX_VALUE;
        if(!allowed(host,host))throw new Excluded(host);
        long now=System.nanoTime();long interval=(long)(1_000_000_000d/configuration.requestsPerSecond());
        long rateWait=lastSend.getOrDefault(host,now-interval)+interval-now;
        if(active>=configuration.concurrency() || activeByHost.getOrDefault(host,0)>=configuration.perHostConcurrency())return Long.MAX_VALUE;
        if(rateWait>0)return rateWait;
        active++;activeByHost.merge(host,1,Integer::sum);sent++;lastSend.put(host,now);return 0;
    }
    private synchronized void release(String host){active--;activeByHost.merge(host,-1,Integer::sum);notifyAll();}
    public com.bypassfuzzer.core.throttle.GlobalTrafficGovernor.LocalAdmission admission(long revision,String host) {
        String key=RunConfiguration.normalizeHost(host);
        return new com.bypassfuzzer.core.throttle.GlobalTrafficGovernor.LocalAdmission(() -> tryAcquire(revision,key),() -> release(key));
    }
    /** Direct transports use the same reservation without an extension/process-wide governor. */
    public <T> T send(long expectedRevision,String host,Callable<T> network) throws Exception {
        host=RunConfiguration.normalizeHost(host);
        synchronized(this) {
            while(true) {
                checkpoint(expectedRevision);long delay=tryAcquire(expectedRevision,host);if(delay==0)break;
                wait(Math.max(1,Math.min(100,delay/1_000_000)));
            }
        }
        try{return network.call();}finally{release(host);}
    }
    /** Replanning reuses payload identities; it never regenerates completed Collaborator probes. */
    public void planningSeed(String seed){planningSeed.set(seed);}
    public Supplier<String> domains(String seed,Supplier<String> generate) {
        String identity=planningSeed.get()==null ? seed : planningSeed.get();
        var next=new java.util.concurrent.atomic.AtomicInteger();
        return () -> outOfBand.computeIfAbsent(identity+"\n"+next.getAndIncrement(),ignored -> {
            String value=generate.get();return value==null ? "" : value;
        });
    }
    @SuppressWarnings("unchecked") public <Q> Q control(String key, Supplier<Q> create) {
        return control(key,snapshot().headerRevision(),create);
    }
    @SuppressWarnings("unchecked") public <Q> Q control(String key,long headerRevision,Supplier<Q> create) {
        return (Q)controlRequests.computeIfAbsent(headerRevision+"\n"+key,ignored -> create.get());
    }
}

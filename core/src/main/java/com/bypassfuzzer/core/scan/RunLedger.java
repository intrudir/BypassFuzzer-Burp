package com.bypassfuzzer.core.scan;

import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/** Retains attempted work across edits; controls are keyed by their header context. */
public final class RunLedger<T> {
    public record Entry<T>(T value, boolean fresh) { }
    private final ConcurrentHashMap<String,T> attempted = new ConcurrentHashMap<>();
    public Entry<T> get(String key, Supplier<T> send) {
        T previous = attempted.get(key);
        if (previous != null) return new Entry<>(previous,false);
        T result = send.get();
        attempted.put(key,result);
        return new Entry<>(result,true);
    }
    public void removeWork(String seed, PlannedRequest probe) {
        String sample=key(seed,probe,0,0);String prefix=sample.substring(0,sample.lastIndexOf("\n")+1);
        attempted.keySet().removeIf(k -> k.startsWith(prefix));
    }
    public void clear(){attempted.clear();}
    public boolean contains(String key) { return attempted.containsKey(key); }
    public static String key(String seed, PlannedRequest probe, long headerRevision, int attempt) {
        return seed+"\n"+probe.request().protocol()+"\n"+probe.controlRole()+"\n"+probe.playbookId()+"\n"+probe.family()+"\n"+probe.payload()+"\n"+probe.encoding()+"\n"+attempt
            +(probe.controlRole()==ControlRole.NONE ? "" : "\nheaders="+headerRevision);
    }
}

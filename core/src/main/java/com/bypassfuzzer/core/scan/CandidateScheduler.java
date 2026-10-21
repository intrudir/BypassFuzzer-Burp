package com.bypassfuzzer.core.scan;
import java.util.*;
import java.util.function.Function;

/** Host interleaving from the master's lazy candidate scheduler. */
public final class CandidateScheduler {
    private CandidateScheduler() { }
    public static <T> List<T> interleave(List<T> candidates, Function<T, String> host) {
        var byHost = new LinkedHashMap<String, ArrayDeque<T>>();
        for (T candidate : candidates) byHost.computeIfAbsent(host.apply(candidate), ignored -> new ArrayDeque<>()).add(candidate);
        var result = new ArrayList<T>(candidates.size());
        while (result.size() < candidates.size()) for (var group : byHost.values()) {
            T candidate = group.poll();
            if (candidate != null) result.add(candidate);
        }
        return List.copyOf(result);
    }
}

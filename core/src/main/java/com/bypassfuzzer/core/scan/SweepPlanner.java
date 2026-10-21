package com.bypassfuzzer.core.scan;

import com.bypassfuzzer.core.http.HttpRequestData;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

/** Burp's control accounting and uncapped full-catalog rules. */
public final class SweepPlanner {
    public List<PlannedRequest> highSignal(HttpRequestData request, Set<String> families,
        int maximum, List<Integer> ports, boolean includeControl) {
        boolean hostEnabled = ports != null && !ports.isEmpty();
        int hostCount = hostEnabled && families.contains("Host Parsing") ? 2 +
            (int) ports.stream().filter(p -> p != null && p >= 1 && p <= 65535).count() * 3 : 0;
        var output = new ArrayList<PlannedRequest>();
        if (includeControl) output.add(PlannedRequest.baseline(request, "Control: original blocked request"));
        output.addAll(new HighSignalPlanner().plan(request, families,
            Math.max(0, Math.max(1, maximum) + hostCount - output.size()), hostEnabled, ports));
        return List.copyOf(output);
    }

    public List<PlannedRequest> all(HttpRequestData request, Set<AttackFamily> families,
        Supplier<String> outOfBand, boolean includeControl) {
        var output = new ArrayList<PlannedRequest>();
        if (includeControl) output.add(PlannedRequest.baseline(request, "Control: original blocked request"));
        output.addAll(new BypassPlanner(outOfBand).plan(request, families, false, Integer.MAX_VALUE));
        return List.copyOf(output);
    }
}

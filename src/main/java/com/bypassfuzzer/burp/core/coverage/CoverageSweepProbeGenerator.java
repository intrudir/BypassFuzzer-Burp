package com.bypassfuzzer.burp.core.coverage;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.http.CoreRequestAdapter;
import com.bypassfuzzer.core.scan.HighSignalPlanner;
import com.bypassfuzzer.core.scan.PlannedRequest;
import java.util.ArrayList;
import java.util.List;

/** Converts the shared high-signal Sweep plan into Burp probe objects. */
public class CoverageSweepProbeGenerator {
    private final CoreRequestAdapter adapter = new CoreRequestAdapter();
    private final HighSignalPlanner planner;

    public CoverageSweepProbeGenerator() { this.planner = new HighSignalPlanner(); }

    CoverageSweepProbeGenerator(List<CoverageSweepProbeTemplate> templates) {
        this.planner = new HighSignalPlanner(templates.stream()
            .map(item -> item.kind() + "|" + item.family() + "|" + item.label() + "|" + item.value())
            .toList());
    }

    public List<CoverageSweepProbe> buildProbes(HttpRequest request, CoverageSweepOptions options) {
        return buildProbes(request, options, true);
    }

    public List<CoverageSweepProbe> buildProbes(HttpRequest request, CoverageSweepOptions options,
                                               boolean includeControl) {
        if (request == null) return List.of();
        int hostCount = 0;
        if (options.hostPortProbesEnabled() && options.familySelection().highSignalEnabled("Host Parsing")) {
            hostCount = 2 + (int) options.hostPortProbePorts().stream()
                .filter(port -> port != null && port >= 1 && port <= 65535).count() * 3;
        }
        int limit = Math.max(1, options.maxProbesPerCandidate()) + hostCount;
        List<CoverageSweepProbe> output = new ArrayList<>();
        if (includeControl) output.add(new CoverageSweepProbe("Control: original blocked request", "Control", request));
        var base = adapter.fromMontoya(request);
        String host = request.headerValue("Host");
        if (host != null && !host.isBlank()) base = base.upsertHeader("Host", host);
        for (PlannedRequest planned : planner.plan(base,
            options.familySelection().highSignalFamilies(), Math.max(0, limit - output.size()),
            options.hostPortProbesEnabled(), options.hostPortProbePorts())) {
            output.add(new CoverageSweepProbe(planned.payload(), planned.family(),
                adapter.toMontoya(request, planned.request()), adapter.httpMode(planned.request().protocol())));
        }
        return List.copyOf(output);
    }
}

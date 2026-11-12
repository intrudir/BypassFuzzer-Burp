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
    private final boolean customTemplates;

    public CoverageSweepProbeGenerator() { this.planner = new HighSignalPlanner(); this.customTemplates = false; }

    CoverageSweepProbeGenerator(List<CoverageSweepProbeTemplate> templates) {
        this.customTemplates = true;
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
        var base = adapter.fromMontoya(request);
        String host = request.headerValue("Host");
        if (host != null && !host.isBlank()) base = base.upsertHeader("Host", host);
        List<PlannedRequest> planned;
        if (customTemplates) {
            int hostCount = options.hostPortProbesEnabled() && options.familySelection().highSignalEnabled("Host Parsing")
                ? 2 + (int) options.hostPortProbePorts().stream().filter(p -> p != null && p >= 1 && p <= 65535).count() * 3 : 0;
            var values = new ArrayList<PlannedRequest>();
            if (includeControl) values.add(PlannedRequest.baseline(base, "Control: original blocked request"));
            values.addAll(planner.plan(base, options.familySelection().highSignalFamilies(),
                Math.max(0, Math.max(1, options.maxProbesPerCandidate()) + hostCount - values.size()),
                options.hostPortProbesEnabled(), options.hostPortProbePorts(), options.playbookOptions()));
            planned = values;
        } else planned = new com.bypassfuzzer.core.scan.SweepPlanner().highSignal(base,
            options.familySelection().highSignalFamilies(), options.maxProbesPerCandidate(),
            options.hostPortProbePorts(), includeControl, options.playbookOptions());
        return planned.stream().map(p -> new CoverageSweepProbe(p.payload(), p.family(),
            adapter.toMontoya(request, p.request()), p.baseline() ? null : adapter.httpMode(p.request().protocol()), p.playbookId(), p.controlRole())).toList();
    }
}

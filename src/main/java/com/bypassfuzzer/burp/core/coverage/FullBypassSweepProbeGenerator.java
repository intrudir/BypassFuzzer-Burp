package com.bypassfuzzer.burp.core.coverage;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.attacks.AttackType;
import com.bypassfuzzer.burp.core.collaborator.CollaboratorSupport;
import com.bypassfuzzer.burp.http.CoreRequestAdapter;
import com.bypassfuzzer.core.scan.AttackFamily;
import com.bypassfuzzer.core.scan.BypassPlanner;
import com.bypassfuzzer.core.scan.PlannedRequest;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** Adapts the shared transport-neutral Bypass catalog into non-sending Sweep probes. */
final class FullBypassSweepProbeGenerator {
    private final MontoyaApi api;
    private final CoreRequestAdapter adapter = new CoreRequestAdapter();

    FullBypassSweepProbeGenerator(MontoyaApi api) {
        this.api = api;
    }

    List<CoverageSweepProbe> buildProbes(HttpRequest request, boolean includeControl,
                                         CoverageSweepFamilySelection familySelection) {
        if (request == null) return List.of();
        Set<AttackFamily> enabled = new LinkedHashSet<>();
        for (AttackType type : familySelection.bypassFamilies()) enabled.add(AttackFamily.parse(type.id()));
        BypassPlanner planner = new BypassPlanner(() -> {
            if (!CollaboratorSupport.isAvailable(api)) return "";
            String payload = CollaboratorSupport.generatePayload(api);
            return payload == null ? "" : payload.replaceFirst("^https?://", "").replaceFirst("/.*$", "");
        });
        List<CoverageSweepProbe> mutations = planner.plan(adapter.fromMontoya(request), enabled, false, Integer.MAX_VALUE)
            .stream().map(planned -> toProbe(request, planned)).toList();
        if (!includeControl) return mutations;
        java.util.ArrayList<CoverageSweepProbe> output = new java.util.ArrayList<>(mutations.size() + 1);
        output.add(new CoverageSweepProbe("Control: original blocked request", "Control", request));
        output.addAll(mutations);
        return List.copyOf(output);
    }

    private CoverageSweepProbe toProbe(HttpRequest original, PlannedRequest planned) {
        return new CoverageSweepProbe(planned.payload(), planned.family(), adapter.toMontoya(original, planned.request()),
            adapter.httpMode(planned.request().protocol()));
    }
}

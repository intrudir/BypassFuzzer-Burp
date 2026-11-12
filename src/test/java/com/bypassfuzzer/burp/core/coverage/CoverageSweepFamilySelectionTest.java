package com.bypassfuzzer.burp.core.coverage;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.attacks.AttackType;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import static com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.request;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;

class CoverageSweepFamilySelectionTest {

    @Test
    void highSignalGeneratorSkipsDisabledFamilies() {
        CoverageSweepFamilySelection selection = new CoverageSweepFamilySelection(
            Set.of("Debug Params"), EnumSet.allOf(AttackType.class));
        CoverageSweepProbeGenerator generator = new CoverageSweepProbeGenerator(List.of(
            new CoverageSweepProbeTemplate("HEADER", "Header", "forwarded", "X-Forwarded-For: 127.0.0.1"),
            new CoverageSweepProbeTemplate("PATH", "Debug Params", "debug", "{PATH}?debug=true")
        ));

        List<CoverageSweepProbe> probes = generator.buildProbes(
            request("/admin", "", "GET", null, ""), options(CoverageSweepPayloadSet.HIGH_SIGNAL, selection));

        assertTrue(probes.stream().anyMatch(probe -> "Debug Params".equals(probe.family())));
        assertFalse(probes.stream().anyMatch(probe -> "Header".equals(probe.family())));
        assertFalse(probes.stream().anyMatch(probe -> "Path Normalization".equals(probe.family())));
    }

    @Test
    void fullBypassGeneratorSkipsDisabledAttackTypes() {
        Set<AttackType> enabled = EnumSet.allOf(AttackType.class);
        enabled.remove(AttackType.HEADER);
        CoverageSweepFamilySelection selection = new CoverageSweepFamilySelection(
            Set.copyOf(CoverageSweepFamilySelection.HIGH_SIGNAL_FAMILIES), enabled);
        MontoyaApi api = mock(MontoyaApi.class, RETURNS_DEEP_STUBS);
        HttpRequest base = request("/admin/users", "", "GET", null, "");

        List<CoverageSweepProbe> probes = new FullBypassSweepProbeGenerator(api)
            .buildProbes(base, true, selection);

        assertFalse(probes.stream().anyMatch(probe -> "Header".equals(probe.family())));
        assertTrue(probes.stream().anyMatch(probe -> "Path".equals(probe.family())));
    }

    private CoverageSweepOptions options(CoverageSweepPayloadSet payloadSet,
                                         CoverageSweepFamilySelection selection) {
        CoverageSweepOptions defaults = CoverageSweepOptions.defaults();
        return new CoverageSweepOptions(
            defaults.statuses(), defaults.inScopeOnly(), defaults.maxCandidates(),
            defaults.maxProbesPerCandidate(), defaults.concurrency(), defaults.perHostConcurrency(),
            defaults.throttleStatusCodes(), defaults.mode(), defaults.authSelection(),
            defaults.excludeStaticAssets(), defaults.verifyUnauthenticatedAccess(),
            defaults.hostPortProbePorts(), defaults.requestHeaders(), payloadSet,
            defaults.posture(), selection);
    }
    @Test void exactSharedSelectionsReachNativeProbesAndGateWriteMethods() {
        var hs = new com.bypassfuzzer.core.scan.PlaybookOptions(Set.of("bypass.verb.method_case"),List.of(),true,false);
        var full = new com.bypassfuzzer.core.scan.PlaybookOptions(Set.of("bypass.header.hop_by_hop_auth"),List.of(),true,false);
        var selection = new CoverageSweepFamilySelection(Set.of("Verb"),Set.of(AttackType.HEADER),hs,full);
        var request=request("/api/v1/admin","x=1","GET",null,"");
        var safe=new CoverageSweepProbeGenerator().buildProbes(request,options(CoverageSweepPayloadSet.HIGH_SIGNAL,selection),false);
        assertTrue(safe.stream().allMatch(p->p.playbookId().equals("bypass.verb.method_case")));
        assertFalse(safe.stream().anyMatch(p->Set.of("post","put").contains(p.request().method())));
        var hops=new FullBypassSweepProbeGenerator(mock(MontoyaApi.class,RETURNS_DEEP_STUBS)).buildProbes(request,false,selection);
        assertTrue(hops.stream().allMatch(p->p.playbookId().equals("bypass.header.hop_by_hop_auth") && p.httpMode()==burp.api.montoya.http.HttpMode.HTTP_1));
        assertTrue(hops.stream().anyMatch(p->"Authorization".equals(p.request().headerValue("Connection"))));
    }

}

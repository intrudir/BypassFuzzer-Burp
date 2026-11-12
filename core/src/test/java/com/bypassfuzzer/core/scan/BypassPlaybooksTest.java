package com.bypassfuzzer.core.scan;

import com.bypassfuzzer.core.http.*;
import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class BypassPlaybooksTest {
    private HttpRequestData seed() { return new RawHttpRequestParser().parse(("GET /api/v1/admin?tenant=42 HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer controlled\r\nX-Unrelated: retained\r\n\r\nbody").getBytes(StandardCharsets.UTF_8), TargetOrigin.parse("https://example.test")); }
    private List<PlannedRequest> one(String id) { return new BypassPlanner().plan(seed(), null, false, Integer.MAX_VALUE,
        new PlaybookOptions(Set.of(id), List.of("/internal-v9"), true, false)); }
    @Test void structuredForwardedAndHopPairsAreGeneratedWithoutLosingContext() {
        var forwarded=one("bypass.header.forwarded");
        assertTrue(forwarded.stream().anyMatch(p->p.request().firstHeader("Forwarded").orElse("").equals("For=\"[::1]\"")));
        var hop=one("bypass.header.hop_by_hop_auth");
        assertTrue(hop.stream().anyMatch(p->p.request().firstHeader("Connection").orElse("").equals("Authorization") && p.request().firstHeader("Authorization").orElse("").equals("Bearer controlled")));
        assertTrue(hop.stream().anyMatch(p->p.request().firstHeader("X-Api-Key").orElse("").equals("bypass")));
        for(var p:hop) {assertEquals(HttpProtocol.HTTP_1,p.request().protocol());assertEquals(seed().origin(),p.request().origin());assertArrayEquals(seed().body(),p.request().body());assertEquals("retained",p.request().firstHeader("X-Unrelated").orElseThrow());}
    }
    @Test void apiAndRefererMutationsPreserveQueriesAndOrigin() {
        assertTrue(one("bypass.path.api_prefix").stream().anyMatch(p->p.request().rawTarget().equals("/internal-v9/api/v1/admin?tenant=42")));
        assertTrue(one("bypass.path.api_version_swap").stream().anyMatch(p->p.request().rawTarget().equals("/api/v1.1/admin?tenant=42")));
        assertTrue(one("bypass.header.trusted_referer").stream().anyMatch(p->p.request().firstHeader("Referer").orElse("").equals("https://example.test/dashboard")));
        assertTrue(one("bypass.verb.method_case").stream().map(p->p.request().method()).toList().containsAll(List.of("get","post","put","head","options","GeT","XGET")));
    }
    @Test void boundedHighSignalCoversEveryNewPlaybookAndGatesWrites() {
        var plan=new HighSignalPlanner().plan(seed(), null, 40);
        var ids=plan.stream().map(PlannedRequest::playbookId).collect(java.util.stream.Collectors.toSet());
        for(var d:BypassPlaybooks.available(BypassPlaybooks.Inventory.HIGH_SIGNAL))assertTrue(ids.contains(d.id()),d.id());
        assertTrue(plan.stream().noneMatch(p->Set.of("post","put").contains(p.request().method())));
        var enabled=new PlaybookOptions(Set.of("bypass.verb.method_case"),List.of(),true,true);
        assertTrue(new HighSignalPlanner().plan(seed(),Set.of("Verb"),100,false,List.of(),enabled).stream().anyMatch(p->p.request().method().equals("post")));
    }
    @Test void selectionIsExactAndInvalidInputFailsBeforePlanning() {
        assertTrue(one("bypass.header.forwarded").stream().allMatch(p->p.playbookId().equals("bypass.header.forwarded")));
        assertThrows(IllegalArgumentException.class,()->BypassPlaybooks.resolve(BypassPlaybooks.Inventory.BYPASS,Set.of("path"),new PlaybookOptions(Set.of("bypass.header.forwarded"),List.of(),true,false)));
        assertThrows(IllegalArgumentException.class,()->new PlaybookOptions(null,List.of("https://other.test"),true,false));
        assertTrue(new BypassPlanner().plan(seed().withProtocol(HttpProtocol.HTTP_2),null,false,100,new PlaybookOptions(Set.of("bypass.header.hop_by_hop_auth"),List.of(),true,false)).isEmpty());
    }
    @Test void emptySelectionEmitsNothingAndShortcutsKeepCountsConsistent() {
        var empty=new PlaybookOptions(Set.of(),List.of(),true,false);
        assertTrue(new BypassPlanner().plan(seed(),null,false,100,empty).isEmpty());
        assertTrue(new HighSignalPlanner().plan(seed(),null,100,false,List.of(),empty).isEmpty());
        var selected=new PlaybookSelection(BypassPlaybooks.Inventory.BYPASS,null);
        var headerOff=selected.withFamily("header",false);
        assertFalse(headerOff.groups().contains("header"));
        assertTrue(selected.ids().size()>headerOff.ids().size());
        assertTrue(headerOff.withFamily("header",true).ids().containsAll(selected.ids()));
    }
    @Test void originalMethodCaseAndEveryLegacyGroupRemainAvailable() {
        var methods=new BypassPlanner().plan(seed().withMethod("M-SEARCH"),Set.of(AttackFamily.VERB),false,Integer.MAX_VALUE);
        assertTrue(methods.stream().map(p->p.request().method()).toList().containsAll(List.of("m-search","M-Search","M-sEaRcH","XM-SEARCH","M-SEARCHX")));
        var all=new BypassPlanner().plan(seed(),null,true,Integer.MAX_VALUE);
        for(var family:AttackFamily.values()) assertTrue(all.stream().anyMatch(p->p.playbookId().equals("bypass."+family.id()+".base")),family.id());
        var multi=new BypassPlanner().plan(seed().withRawTarget("/v1/api/v2/admin?x=1"),null,false,100,
            new PlaybookOptions(Set.of("bypass.path.api_version_swap"),List.of(),true,false));
        assertTrue(multi.stream().anyMatch(p->p.request().rawTarget().equals("/v1/api/v4/admin?x=1")));
    }

}

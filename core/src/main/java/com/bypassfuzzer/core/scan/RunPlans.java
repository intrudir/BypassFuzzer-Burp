package com.bypassfuzzer.core.scan;

import com.bypassfuzzer.core.http.*;
import com.bypassfuzzer.core.urlvalidation.*;
import java.util.*;

/** Adapts the existing mode catalogs to one editable selection model. */
public final class RunPlans {
    private RunPlans() { }
    public static Map<String,String> bypass(BypassPlaybooks.Inventory inventory) {
        var values = new LinkedHashMap<String,String>();
        for (var d : BypassPlaybooks.available(inventory)) values.put(d.id(),d.label());
        return values;
    }
    public static Map<String,String> idor() {
        var values = new LinkedHashMap<String,String>();
        for (String id : new IdorPlanner().availableFamilies()) values.put(id,new IdorPlanner().dangerousFamilyRisks().containsKey(id) ? id+" — DANGEROUS: other identifiers" : id);
        return values;
    }
    public static Map<String,String> url() {
        var values = new LinkedHashMap<String,String>();
        for (var c : UrlValidationContext.values()) values.put("url.context."+c.name(),c.displayName());
        for (var a : UrlValidationAttackSetting.values()) values.put("url.attack."+a.name(),a.toString());
        return values;
    }
    public static Set<String> urlSelection(UrlValidationOptions options) {
        var ids = new LinkedHashSet<String>();
        options.normalizedPayloadFamilies().forEach(c -> ids.add("url.context."+c.name()));
        options.normalizedAttackSettings().forEach(a -> ids.add("url.attack."+a.name()));
        return ids;
    }
    public static PlaybookOptions bypassOptions(LiveRun live, PlaybookOptions original) {
        return live == null ? original : original.withSelection(live.snapshot().configuration().playbooks());
    }
    public static IdorPlanOptions idorOptions(LiveRun live, IdorPlanOptions original) {
        Set<String> ids = live == null ? original.families() : live.snapshot().configuration().playbooks();
        return new IdorPlanOptions(original.authorizedId(),original.targetId(),original.locationKey(),
            ids == null || ids.isEmpty() ? original.families() : ids,original.maxMutations(),original.includeMethodChanges(),original.uniqueJsonPointer(),live!=null && live.snapshot().revision()>0 && original.uniqueToken()!=null ? original.uniqueToken()+"-r"+live.snapshot().revision() : original.uniqueToken());
    }
    public static List<PlannedRequest> idorAfter(LiveRun live, HttpRequestData base, IdorPlanOptions options,
                                                HttpResponseData authorized, HttpResponseData target) {
        if (live != null && live.snapshot().configuration().playbooks()!=null && live.snapshot().configuration().playbooks().isEmpty()) return List.of();
        return new ResponseGuidedIdorPlanner().plan(base,idorOptions(live,options),authorized,target);
    }
    public static List<PlannedRequest> urlPlan(LiveRun live, HttpRequestData base, UrlValidationOptions original, int maximum) {
        if (live == null || live.snapshot().configuration().playbooks()==null) return new UrlValidationPlanner().plan(base,original,maximum);
        var ids = live.snapshot().configuration().playbooks();
        var contexts = EnumSet.noneOf(UrlValidationContext.class);
        var attacks = EnumSet.noneOf(UrlValidationAttackSetting.class);
        for (var c : UrlValidationContext.values()) if (ids.contains("url.context."+c.name())) contexts.add(c);
        for (var a : UrlValidationAttackSetting.values()) if (ids.contains("url.attack."+a.name())) attacks.add(a);
        if (contexts.isEmpty() || attacks.isEmpty()) return List.of(PlannedRequest.baseline(base,"url-validation.baseline"));
        return new UrlValidationPlanner().plan(base,new UrlValidationOptions(original.markerText(),original.allowedHost(),original.attackerHost(),
            original.attackerScheme(),contexts,attacks,original.encodings()),maximum);
    }
    public static void validateIdor(RunConfiguration config,HttpRequestData original,IdorPlanOptions options) {
        if(config.excludes(original.origin().host()))return;
        var locations=IdentifierLocation.discover(config.prepare(original,RequestAccess.CORE),options.authorizedId());
        if(options.locationKey()==null || options.locationKey().isBlank()) {
            if(locations.size()!=1)throw new IllegalArgumentException("Header edit changes identifier discovery; keep the selected identifier slot or start a new run");
        }else if(locations.stream().noneMatch(location -> location.key().equals(options.locationKey())))
            throw new IllegalArgumentException("Header edit removes the selected identifier slot; start a new run to change identifiers");
    }
    public static String savedId(String family,String playbook) {
        if(playbook!=null && !playbook.isEmpty())return playbook;
        if(family!=null && family.startsWith("idor."))return family;
        return "saved."+java.util.Base64.getUrlEncoder().withoutPadding().encodeToString((family==null ? "" : family).getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
    public static Map<String,String> savedCatalog(java.util.Collection<PlannedRequest> saved) {
        var ids=new LinkedHashMap<String,String>();
        for(var probe:saved)if(probe.controlRole()==ControlRole.NONE) {
            String id=savedId(probe.family(),probe.playbookId());ids.putIfAbsent(id,probe.family()+" — "+id);
        }
        return ids;
    }
    public static String checkId(PlannedRequest probe) {
        return probe.playbookId().isEmpty() && probe.family().startsWith("idor.") ? probe.family() : probe.playbookId();
    }
}

package com.bypassfuzzer.core.scan;

import com.bypassfuzzer.core.http.*;
import java.util.*;
import java.util.regex.Pattern;

/** Authoritative descriptions, selection rules and added generators for both scan surfaces. */
public final class BypassPlaybooks {
    public enum Inventory { BYPASS, HIGH_SIGNAL }
    public record Descriptor(String id, String label, AttackFamily family, String highSignalFamily,
                             String description, boolean http1Only, boolean added) {
        public boolean defaultEnabled() { return true; }
        public Set<Inventory> inventories() { return family == null ? Set.of(Inventory.HIGH_SIGNAL) : highSignalFamily.isEmpty() ? Set.of(Inventory.BYPASS) : Set.of(Inventory.BYPASS,Inventory.HIGH_SIGNAL); }
    }
    private static final List<String> PREFIXES = List.of("/v2", "/v3", "/api/v1", "/api/v2", "/api");
    private static final Pattern VERSION = Pattern.compile("(?<=/)v[0-9]+(?=/|$)");
    private static final List<Descriptor> CATALOG;
    static {
        List<Descriptor> entries = new ArrayList<>();
        for (AttackFamily family : AttackFamily.values()) entries.add(new Descriptor("bypass." + family.id() + ".base",
            family.displayName() + " inventory", family, "", "Existing " + family.displayName() + " mutations", false, false));
        for (String group : List.of("Matrix / Extension", "Extension / Negotiation", "Path Normalization", "Encoding", "Debug Params", "Content-Type", "Header", "Host Parsing"))
            entries.add(new Descriptor(highSignalId(group), group + " inventory", null, group, "Curated " + group + " probes", false, false));
        entries.add(new Descriptor("bypass.header.forwarded", "Structured Forwarded", AttackFamily.HEADER, "Header", "RFC 7239 for=/For= node values, including quoted IPv6", false, true));
        entries.add(new Descriptor("bypass.header.hop_by_hop_auth", "Hop-by-hop authentication", AttackFamily.HEADER, "Header", "Connection nominations with captured and sentinel authentication headers (HTTP/1 only)", true, true));
        entries.add(new Descriptor("bypass.header.trusted_referer", "Trusted-path Referer", AttackFamily.HEADER, "Header", "Same-origin admin, dashboard and internal Referers", false, true));
        entries.add(new Descriptor("bypass.path.api_prefix", "API prefix insertion", AttackFamily.PATH, "Path Normalization", "Built-in and additional API prefixes; same socket destination", false, true));
        entries.add(new Descriptor("bypass.path.api_version_swap", "API version substitution", AttackFamily.PATH, "Path Normalization", "Alternate vN path versions", false, true));
        entries.add(new Descriptor("bypass.verb.method_case", "Method case", AttackFamily.VERB, "Verb", "Original method case variants and lowercase get/post/put/head/options", false, true));
        CATALOG = List.copyOf(entries);
    }
    private BypassPlaybooks() { }
    public static String highSignalId(String family) { return "sweep.high_signal." + family.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "_") + ".base"; }
    public static List<Descriptor> available(Inventory inventory) {
        return CATALOG.stream().filter(d -> inventory == Inventory.BYPASS ? d.family() != null : !d.highSignalFamily().isEmpty()).toList();
    }
    public static Set<String> resolve(Inventory inventory, Set<String> families, PlaybookOptions options) {
        Set<String> allowed = new LinkedHashSet<>();
        for (Descriptor d : available(inventory)) {
            String group = inventory == Inventory.BYPASS ? d.family().id() : d.highSignalFamily();
            if (families == null || families.contains(group)) allowed.add(d.id());
        }
        if (options.selected() == null) return Collections.unmodifiableSet(allowed);
        for (String id : options.selected()) if (!allowed.contains(id))
            throw new IllegalArgumentException("Playbook is unknown, unavailable in this inventory, or excluded by families: " + id);
        return options.selected();
    }
    public static List<PlannedRequest> added(Descriptor descriptor, HttpRequestData request, PlaybookOptions options, Inventory inventory) {
        List<PlannedRequest> output = new ArrayList<>();
        switch (descriptor.id()) {
            case "bypass.header.forwarded" -> {
                List<String> ips = inventory == Inventory.HIGH_SIGNAL ? List.of("127.0.0.1", "0.0.0.0", "127.1.1.1", "::1", "192.168.1.1") : ResourcePayloads.load("ip_payloads.txt");
                for (String ip : ips) for (String key : List.of("for", "For")) {
                    String value = key + "=" + (ip.contains(":") ? "\"[" + ip + "]\"" : ip);
                    add(output, descriptor, "Forwarded: " + value, request.upsertHeader("Forwarded", value), inventory);
                }
            }
            case "bypass.header.hop_by_hop_auth" -> {
                if (request.protocol() == HttpProtocol.HTTP_2) return List.of();
                for (String header : List.of("Authorization", "Cookie", "X-Api-Key", "X-Auth-Token", "X-Access-Token")) {
                    var base = request.withProtocol(HttpProtocol.HTTP_1).upsertHeader("Connection", header);
                    if (request.firstHeader(header).isPresent()) add(output, descriptor, "Connection: " + header + " (captured value)", base, inventory);
                    add(output, descriptor, "Connection: " + header + "; " + header + ": bypass", base.upsertHeader(header, "bypass"), inventory);
                }
            }
            case "bypass.header.trusted_referer" -> {
                for (String path : List.of("/admin", "/dashboard", "/internal")) {
                    String value = request.origin() + path;
                    add(output, descriptor, "Referer: " + value, request.upsertHeader("Referer", value), inventory);
                }
            }
            case "bypass.path.api_prefix" -> {
                Set<String> prefixes = new LinkedHashSet<>(PREFIXES); prefixes.addAll(options.apiPrefixes());
                for (String prefix : prefixes) add(output, descriptor, prefix + request.rawTarget(), request.withRawTarget(prefix.replaceAll("/+$", "") + request.rawTarget()), inventory);
            }
            case "bypass.path.api_version_swap" -> {
                var matcher = VERSION.matcher(request.path());
                while (matcher.find()) for (String version : List.of("v2", "v3", "v4", "v1.1", "v2.0")) {
                    String path = request.path().substring(0,matcher.start()) + version + request.path().substring(matcher.end());
                    if (path.equals(request.path())) continue;
                    String target = path + request.rawTarget().substring(request.path().length());
                    add(output, descriptor, target, request.withRawTarget(target), inventory);
                }
            }
            case "bypass.verb.method_case" -> {
                Set<String> methods = new LinkedHashSet<>(List.of("get", "post", "put", "head", "options"));
                if (inventory == Inventory.BYPASS) {
                    String original = request.method(); methods.add(original.toLowerCase(Locale.ROOT));
                    StringBuilder title = new StringBuilder(); boolean upper = true;
                    for (char ch : original.toCharArray()) {
                        if ("/?&=_-".indexOf(ch) >= 0) { title.append(ch); upper=true; }
                        else { title.append(upper ? Character.toUpperCase(ch) : Character.toLowerCase(ch)); upper=false; }
                    }
                    methods.add(title.toString());
                    StringBuilder mixed = new StringBuilder(); int index=0;
                    for (char ch : original.toCharArray()) mixed.append(Character.isLetter(ch) ? ((index++ & 1)==0 ? Character.toUpperCase(ch) : Character.toLowerCase(ch)) : ch);
                    methods.add(mixed.toString()); methods.add("X"+original); methods.add(original+"X");
                }
                for (String method : methods) {
                    if (inventory == Inventory.HIGH_SIGNAL && !options.includeStateChanging() && Set.of("post", "put").contains(method)) continue;
                    add(output, descriptor, "Method: " + method, request.withMethod(method), inventory);
                }
            }
            default -> throw new IllegalArgumentException("No generator for " + descriptor.id());
        }
        return List.copyOf(output);
    }
    private static void add(List<PlannedRequest> out, Descriptor d, String label, HttpRequestData request, Inventory inventory) {
        out.add(new PlannedRequest(inventory == Inventory.BYPASS ? d.family().displayName() : d.highSignalFamily(), label, "", request, false).withPlaybook(d.id()));
    }
    public static List<PlannedRequest> fair(List<List<PlannedRequest>> groups, int maximum) {
        List<PlannedRequest> result = new ArrayList<>(); Set<String> seen = new HashSet<>();
        for (int index=0;result.size()<maximum;index++) {
            boolean remaining=false;
            for (var group:groups) {
                if(index>=group.size())continue; remaining=true; var item=group.get(index);var r=item.request();
                String key=item.family()+"\n"+r.protocol()+"\n"+r.toRaw();
                if(seen.add(key))result.add(item);
                if(result.size()>=maximum)break;
            }
            if(!remaining)break;
        }
        return List.copyOf(result);
    }
}

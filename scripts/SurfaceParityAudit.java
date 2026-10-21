package com.bypassfuzzer.burp.core.coverage;
import com.bypassfuzzer.core.http.UserAgentMode;
import com.bypassfuzzer.core.http.ConfiguredHeader;

import com.bypassfuzzer.cli.BypassFuzzerCli;
import com.bypassfuzzer.cli.config.YamlJob;
import com.bypassfuzzer.burp.http.*;
import com.bypassfuzzer.burp.testsupport.HeaderRequestTestFactory;
import com.bypassfuzzer.core.http.*;
import com.bypassfuzzer.core.scan.*;
import com.google.gson.GsonBuilder;
import picocli.CommandLine;

import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;

/** Diagnostic probe, run by audit-cli-parity.py; never sends network traffic. */
public class SurfaceParityAudit {
    private static final List<Map<String, Object>> checks = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        var original = HeaderRequestTestFactory.request("GET", "/private/reports/quarterly?id=alice", "",
            List.of(Map.entry("Host", "example.com"), Map.entry("Authorization", "Bearer audit")));
        var adapter = new CoreRequestAdapter();
        var base = adapter.fromMontoya(original);
        var families = EnumSet.allOf(AttackFamily.class);
        var full = new BypassPlanner().plan(base, families, false, Integer.MAX_VALUE);
        var cliSweep = resolved("sweep");
        int sweepCap = (Integer) accessor(cliSweep, "maxProbes");
        var burpFull = new FullBypassSweepProbeGenerator(null).buildProbes(original, false,
            CoverageSweepFamilySelection.defaults());
        // Param/Cookie deliberately randomize case using an unseeded Random.
        // Compare deterministic families rather than misreporting random draws as drift.
        Set<String> stochastic = Set.of("Param", "Cookie");
        boolean stableLabelsMatch = full.stream().filter(p -> !stochastic.contains(p.family()))
            .map(PlannedRequest::payload).toList().equals(burpFull.stream()
                .filter(p -> !stochastic.contains(p.family())).map(CoverageSweepProbe::label).toList());
        check("bypass-family-inventory", stableLabelsMatch, Map.of("families", families.size(),
            "plannedMutations", full.size(), "burpSweepMutations", burpFull.size(),
            "note", "Both entrypoints use BypassPlanner. Compared ordered labels for deterministic families; Param/Cookie use unseeded random casing. This is not a wire-equivalence proof."));
        var cliAll = preview(base, "sweep", "--payload-set", "all");
        var cliAllStable = cliAll.stream().map(Preview::label).filter(label -> !label.startsWith("Control:")).toList();
        var expectedStable = burpFull.stream().filter(p -> !stochastic.contains(p.family())).map(CoverageSweepProbe::label).toList();
        var expectedLabels = new HashSet<>(expectedStable);
        check("sweep-all-payloads", cliAll.size() > 10_000 && cliAllStable.stream().filter(expectedLabels::contains).toList().equals(expectedStable),
            Map.of("burpMutations", burpFull.size(), "cliPlannedRequests", cliAll.size(), "highSignalBudget", sweepCap));

        var options = CoverageSweepOptions.defaults();
        var burpHigh = new CoverageSweepProbeGenerator().buildProbes(original, options, false);
        var cliHigh = preview(base, "sweep").stream().filter(p -> !p.label().startsWith("Control:")).toList();
        Set<String> burpLabels = new TreeSet<>(), cliLabels = new TreeSet<>();
        burpHigh.forEach(p -> burpLabels.add(p.label()));
        cliHigh.forEach(p -> cliLabels.add(p.label()));
        var cliOnly = new TreeSet<>(cliLabels); cliOnly.removeAll(burpLabels);
        var burpOnly = new TreeSet<>(burpLabels); burpOnly.removeAll(cliLabels);
        check("high-signal-default-inventory", burpLabels.equals(cliLabels), Map.of(
            "burpCount", burpHigh.size(), "cliCount", cliHigh.size(),
            "burpOnly", burpOnly, "cliOnly", cliOnly));

        var custom = new CoverageSweepProbeGenerator().buildProbes(original,
            options.withHostPortProbePorts(List.of(8443)), false);
        var cliOptions = new TreeMap<String, Set<String>>();
        new CommandLine(new BypassFuzzerCli()).getSubcommands().forEach((name, command) -> {
            var names = new TreeSet<String>();
            command.getCommandSpec().options().forEach(option -> names.addAll(List.of(option.names())));
            cliOptions.put(name, names);
        });
        check("oob-host-adapter", cliOptions.get("bypass").containsAll(Set.of("--oob-domain", "--oob-generator"))
            && cliOptions.get("url-validation").containsAll(Set.of("--oob-domain", "--oob-generator")),
            Map.of("source", "core.scan.OutOfBandSource", "proof", "CliParityTest.outOfBandPayloadsUseTheSharedHeaderInventory"));
        check("run-control-and-global-admission", cliOptions.get("sweep").containsAll(
            Set.of("--control-file", "--traffic-max-in-flight", "--traffic-max-rps")),
            Map.of("source", "core.throttle.GlobalTrafficGovernor", "proof", "CliParityTest.resumeAndDashboardRateLimitGovernRealSends"));
        check("result-filter-and-export-surface", cliOptions.containsKey("results") && cliOptions.get("results")
            .containsAll(Set.of("--format", "--smart-repeats", "--response-regex", "--signal-regex", "--show-status")),
            Map.of("source", "core.filter", "proof", "CliParityTest.contentTypeSignalAndResultFiltersFollowTheBurpRules"));
        check("custom-host-ports", cliOptions.get("sweep").contains("--host-ports"), Map.of(
            "burpCustomPortProbes", custom.stream().filter(p -> p.label().contains("8443")).count(),
            "cliSweepOptions", cliOptions.get("sweep")));
        check("authenticated-sweep", cliOptions.get("sweep").contains("--sweep-mode"), Map.of(
            "burpModes", Arrays.stream(CoverageSweepMode.values()).map(Enum::name).toList(),
            "note", "CLI maps authenticated controls to the same SweepWorkflow; live tests verify credential stripping and public endpoint skipping."));

        var headersCommand = command("bypass", "--header", "X-Audit: first", "--header", "X-Audit: second");
        var prepared = prepare(headersCommand, base);
        var burpHeaders = new ConfiguredHeaderPolicy(List.of(new ConfiguredHeader("X-Audit", "first"),
            new ConfiguredHeader("X-Audit", "second"))).applyToBase(original);
        var burpValues = HeaderRequestTestFactory.values(burpHeaders, "X-Audit");
        var cliValues = prepared.headers().stream().filter(h -> h.name().equalsIgnoreCase("X-Audit"))
            .map(HttpHeader::value).toList();
        check("configured-duplicate-headers", burpValues.equals(cliValues), Map.of(
            "burp", burpValues, "cli", cliValues));

        var policy = new ConfiguredHeaderPolicy(List.of(new ConfiguredHeader("X-Forwarded-For", "configured")));
        var burpMutation = policy.reconcileMutation(original,
            original.withUpdatedHeader("X-Forwarded-For", "127.0.0.1"));
        var cliHeaderPreview = preview(base, "bypass", "--families", "header", "--header", "X-Forwarded-For: configured");
        var cliMutation = parse(cliHeaderPreview.stream().filter(p -> p.label().equals("X-Forwarded-For: 127.0.0.1"))
            .findFirst().orElseThrow(), base);
        burpValues = HeaderRequestTestFactory.values(burpMutation, "X-Forwarded-For");
        cliValues = cliMutation.headers().stream().filter(h -> h.name().equalsIgnoreCase("X-Forwarded-For"))
            .map(HttpHeader::value).toList();
        check("configured-header-mutation", burpValues.equals(cliValues), Map.of("burp", burpValues, "cli", cliValues));

        var uaPolicy = new ConfiguredHeaderPolicy(List.of(), UserAgentMode.SYNTHETIC, 42L);
        var ua1 = uaPolicy.reconcileMutation(original, original.withPath("/first")).headerValue("User-Agent");
        var ua2 = uaPolicy.reconcileMutation(original, original.withPath("/second")).headerValue("User-Agent");
        var uaPreview = preview(base, "bypass", "--families", "case", "--user-agent-mode", "synthetic", "--user-agent-seed", "42");
        var cliUaValues = uaPreview.stream().map(p -> parse(p, base).firstHeader("User-Agent").orElse("")).distinct().toList();
        check("per-mutation-user-agent", !ua1.equals(ua2) && cliUaValues.size() > 1, Map.of(
            "burpTwoMutations", List.of(ua1, ua2), "cliDistinctValues", cliUaValues));

        var configured = resolved("bypass");
        var execution = accessor(configured, "options");
        var bypassCap = (Integer) accessor(configured, "maxProbes");
        check("bypass-full-inventory", bypassCap >= full.size(), Map.of(
            "burpUnlimitedMutations", full.size(), "cliDefaultLimit", bypassCap));
        check("retry-defaults", accessor(execution, "retryAttempts").equals(3), Map.of(
            "burpBypassRetries", 3, "cliRetries", accessor(execution, "retryAttempts"),
            "burpUrlValidationRetries", 0, "note", "Defaults follow the master: Bypass three retries, URL Validation zero."));

        var contentResponse = new HttpResponseData(HttpProtocol.HTTP_1, 200,
            List.of(new HttpHeader("Content-Type", "text/plain")), new byte[]{1}, 0);
        var changedType = new HttpResponseData(HttpProtocol.HTTP_1, 200,
            List.of(new HttpHeader("Content-Type", "application/json")), new byte[]{1}, 0);
        var events = new ArrayList<ScanEvent>();
        var engine = new ScanEngine(new ScanOptions(HttpProtocol.HTTP_1, Duration.ofSeconds(1),
            1, 1, Set.of(429, 503), 0, false, "ride-hard", "off", 1000));
        engine.run("sweep", List.of(base), r -> List.of(new PlannedRequest("Header", "probe", "", r, false)),
            (r, t) -> events.isEmpty() ? contentResponse : changedType, events::add);
        String signal = events.get(1).signal();
        var burpResponse = org.mockito.Mockito.mock(burp.api.montoya.http.message.responses.HttpResponse.class);
        var burpType = org.mockito.Mockito.mock(burp.api.montoya.http.message.HttpHeader.class);
        var burpBody = org.mockito.Mockito.mock(burp.api.montoya.core.ByteArray.class);
        org.mockito.Mockito.when(burpType.name()).thenReturn("Content-Type");
        org.mockito.Mockito.when(burpType.value()).thenReturn("application/json");
        org.mockito.Mockito.when(burpResponse.headers()).thenReturn(List.of(burpType));
        org.mockito.Mockito.when(burpResponse.statusCode()).thenReturn((short) 200);
        org.mockito.Mockito.when(burpBody.length()).thenReturn(1);
        org.mockito.Mockito.when(burpResponse.body()).thenReturn(burpBody);
        var candidate = new CoverageSweepCandidate(original, null, "audit", original.url(),
            "GET", "example.com", "/private", 200, 1, "text/plain", null);
        String burpSignal = CoverageSweepClassifier.signal(candidate, null, burpResponse);
        check("sweep-content-type-classification", burpSignal.equals(signal),
            Map.of("cliSignal", signal, "burpSignal", burpSignal));

        var burpUrlOptions = new com.bypassfuzzer.burp.core.urlvalidation.UrlValidationOptions(
            "{INJECT}", "trusted.example", "audit.example", false, "https", null, null, null, Set.of(429, 503));
        var burpGenerator = new com.bypassfuzzer.burp.core.urlvalidation.UrlValidationPayloadGenerator();
        var burpUrlCandidate = new com.bypassfuzzer.burp.core.urlvalidation.UrlValidationCandidate(
            "{INJECT}", "{INJECT}", "marker", null);
        var burpPayloads = burpGenerator.generate(burpUrlCandidate, burpUrlOptions);
        var corePayloads = new com.bypassfuzzer.core.urlvalidation.UrlValidationPayloadGenerator().generate(
            new com.bypassfuzzer.core.urlvalidation.UrlValidationCandidate("{INJECT}", "{INJECT}", "marker"),
            com.bypassfuzzer.burp.core.urlvalidation.UrlValidationPayloadGenerator.toCoreOptions(
                burpUrlOptions, "audit.example"));
        check("url-validation-payload-adapter", burpPayloads.stream().map(p -> p.value()).toList()
            .equals(corePayloads.stream().map(p -> p.value()).toList()), Map.of(
                "burpPayloads", burpPayloads.size(), "corePayloads", corePayloads.size(),
                "note", "Default URL Validation payloads with an explicit host; excludes Collaborator."));

        var result = new LinkedHashMap<String, Object>();
        result.put("checks", checks);
        result.put("idorSharedFamilies", new IdorPlanner().availableFamilies());
        result.put("cliOptions", cliOptions);
        Files.writeString(Path.of(args[0]), new GsonBuilder().setPrettyPrinting().create().toJson(result) + "\n");
    }

    private record Preview(String label, String raw) { }
    private static HttpRequestData parse(Preview preview, HttpRequestData base) {
        return new RawHttpRequestParser().parse(preview.raw().getBytes(java.nio.charset.StandardCharsets.ISO_8859_1), base.origin());
    }
    private static List<Preview> preview(HttpRequestData base, String... arguments) throws Exception {
        Path file = Files.createTempFile("bypassfuzzer-parity-input-", ".raw");
        var output = new java.io.ByteArrayOutputStream();
        java.io.PrintStream saved = System.out;
        try {
            Files.write(file, base.toRaw().getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
            var args = new ArrayList<>(List.of(arguments));
            args.addAll(List.of("--preview", "--request", file.toString(), "--target-origin", base.origin().toString()));
            System.setOut(new java.io.PrintStream(output, true, java.nio.charset.StandardCharsets.UTF_8));
            int code = new CommandLine(new BypassFuzzerCli()).execute(args.toArray(String[]::new));
            if (code != 0) throw new IllegalStateException("CLI preview exited " + code);
        } finally { System.setOut(saved); Files.deleteIfExists(file); }
        String text = output.toString(java.nio.charset.StandardCharsets.UTF_8);
        var matches = java.util.regex.Pattern.compile("(?m)^=== (.*) ===\\R").matcher(text);
        var headers = new ArrayList<String>();
        var starts = new ArrayList<Integer>();
        var ends = new ArrayList<Integer>();
        while (matches.find()) { headers.add(matches.group(1)); starts.add(matches.start()); ends.add(matches.end()); }
        var results = new ArrayList<Preview>();
        for (int index = 0; index < headers.size(); index++) {
            int end = index + 1 < starts.size() ? starts.get(index + 1) : text.length();
            results.add(new Preview(headers.get(index), text.substring(ends.get(index), end).replaceFirst("\\R$", "")));
        }
        return results;
    }

    private static CommandLine command(String... args) {
        var cli = new CommandLine(new BypassFuzzerCli());
        cli.parseArgs(args);
        return cli.getSubcommands().get(args[0]);
    }
    private static Object resolved(String mode) throws Exception {
        return resolve(command(mode));
    }
    private static Object resolve(CommandLine command) throws Exception {
        return invoke(command.getCommand(), "common", YamlJob.load(null), command.getCommandName());
    }
    @SuppressWarnings("unchecked")
    private static HttpRequestData prepare(CommandLine command, HttpRequestData base) throws Exception {
        return ((List<HttpRequestData>) invoke(command.getCommand(), "prepare", List.of(base), resolve(command))).get(0);
    }
    private static Object accessor(Object object, String name) throws Exception { return invoke(object, name); }
    private static Object invoke(Object object, String name, Object... args) throws Exception {
        for (Class<?> type = object.getClass(); type != null; type = type.getSuperclass()) {
            for (Method method : type.getDeclaredMethods()) {
                if (method.getName().equals(name) && method.getParameterCount() == args.length) {
                    method.setAccessible(true);
                    return method.invoke(object, args);
                }
            }
        }
        throw new NoSuchMethodException(name);
    }
    private static void check(String id, boolean pass, Map<String, Object> evidence) {
        checks.add(Map.of("id", id, "status", pass ? "PASS" : "FAIL", "evidence", evidence));
    }
}

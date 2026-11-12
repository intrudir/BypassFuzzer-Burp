package com.bypassfuzzer.cli;

import com.bypassfuzzer.cli.config.YamlJob;
import com.bypassfuzzer.cli.evidence.EvidenceWriter;
import com.bypassfuzzer.cli.input.CliRequestLoader;
import com.bypassfuzzer.cli.run.ExecutionOptions;
import com.bypassfuzzer.cli.run.ScanExecutor;
import com.bypassfuzzer.cli.transport.NettyRequestTransport;
import com.bypassfuzzer.core.http.HttpProtocol;
import com.bypassfuzzer.core.http.ConfiguredHeaderParser;
import com.bypassfuzzer.core.http.RequestHeaderPolicy;
import com.bypassfuzzer.core.http.RequestAccess;
import com.bypassfuzzer.core.http.UserAgentMode;
import com.bypassfuzzer.core.scan.ScanDefaults;
import com.bypassfuzzer.core.scan.SweepPlanner;
import com.bypassfuzzer.core.scan.OutOfBandSource;
import com.bypassfuzzer.core.http.HttpRequestData;
import com.bypassfuzzer.core.http.HttpResponseData;
import com.bypassfuzzer.core.http.RawHttpResponseParser;
import com.bypassfuzzer.core.input.OpenApiImportOptions;
import com.bypassfuzzer.core.scan.AttackFamily;
import com.bypassfuzzer.core.scan.BypassPlanner;
import com.bypassfuzzer.core.scan.HighSignalPlanner;
import com.bypassfuzzer.core.scan.IdorPlanner;
import com.bypassfuzzer.core.scan.IdorPlanOptions;
import com.bypassfuzzer.core.scan.PayloadSet;
import com.bypassfuzzer.core.scan.PlannedRequest;
import com.bypassfuzzer.core.scan.ResponseGuidedIdorPlanner;
import com.bypassfuzzer.core.scan.ScanEngine;
import com.bypassfuzzer.core.scan.UrlValidationPlanner;
import com.bypassfuzzer.core.urlvalidation.UrlValidationAttackSetting;
import com.bypassfuzzer.core.urlvalidation.UrlValidationContext;
import com.bypassfuzzer.core.urlvalidation.UrlValidationEncoding;
import com.bypassfuzzer.core.urlvalidation.UrlValidationOptions;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;
import picocli.CommandLine.Spec;
import picocli.CommandLine.Model.CommandSpec;

import java.nio.file.Path;
import java.nio.file.Files;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.function.Function;

@Command(name = "bypassfuzzer", mixinStandardHelpOptions = true, versionProvider = BypassFuzzerCli.Version.class,
    description = "Authorization-bypass fuzzing for authorized targets.",
    subcommands = {BypassFuzzerCli.Sweep.class, BypassFuzzerCli.Bypass.class,
        BypassFuzzerCli.Idor.class, BypassFuzzerCli.UrlValidation.class, ResultsCommand.class})
public final class BypassFuzzerCli implements Runnable {
    @Override public void run() { CommandLine.usage(this, System.out); }

    public static void main(String[] args) {
        int code = new CommandLine(new BypassFuzzerCli()).setCaseInsensitiveEnumValuesAllowed(true).execute(args);
        System.exit(code);
    }

    static final class Version implements CommandLine.IVersionProvider {
        @Override public String[] getVersion() {
            String version = BypassFuzzerCli.class.getPackage().getImplementationVersion();
            return new String[]{"BypassFuzzer CLI " + (version == null ? "development" : version)};
        }
    }

    static class CommonOptions {
        @Option(names = "--control-file", description = "File containing pause, resume, or stop; checked during the run.") Path controlFile;
        @Option(names = "--traffic-max-in-flight", description = "Dashboard-style total physical request cap.") Integer trafficMaxInFlight;
        @Option(names = "--traffic-max-rps", description = "Dashboard-style per-host requests/second limit.") Double trafficMaxRps;
        @Option(names = "--preview", description = "Print planned wire requests without sending traffic.") boolean preview;
        @Option(names = "--oob-domain", description = "Native Collaborator or operator-controlled OOB hostname.") String oobDomain;
        @Option(names = "--oob-generator", description = "Executable that prints a fresh OOB hostname per invocation.") Path oobGenerator;
        @Option(names = "--config", description = "Version-1 YAML job file.") Path config;
        @Option(names = "--output", description = "Evidence output directory.") Path output;
        @Option(names = "--protocol", description = "auto, http1, http2, or both.") String protocol;
        @Option(names = "--proxy", description = "HTTP CONNECT proxy URL.") String proxy;
        @Option(names = "--insecure", description = "Disable TLS certificate verification.") Boolean insecure;
        @Option(names = "--request-timeout", description = "Request timeout in seconds.") Integer requestTimeout;
        @Option(names = "--connect-timeout", description = "Connection timeout in seconds.") Integer connectTimeout;
        @Option(names = "--global-concurrency", description = "Maximum total in-flight requests.") Integer globalConcurrency;
        @Option(names = "--per-host-concurrency", description = "Maximum in-flight requests per host.") Integer perHostConcurrency;
        @Option(names = "--throttle-codes", split = ",", description = "HTTP status codes treated as throttling.") List<Integer> throttleCodes;
        @Option(names = "--retry-attempts", description = "Retries for no-response or throttled requests.") Integer retryAttempts;
        @Option(names = "--max-probes", description = "Maximum mutations per input (not supported by IDOR).") Integer maxProbes;
        @Option(names = "--redact", description = "Redact common credential headers in stored evidence.") Boolean redact;
        @Option(names = "--header", description = "Always-send header; repeatable, ordered duplicates retained.") List<String> headers;
        @Option(names = "--user-agent-mode", description = "disabled, synthetic, or browser-like.") String userAgentMode;
        @Option(names = "--user-agent-seed", description = "Seed for repeatable User-Agent variation.") Long userAgentSeed;
        @Option(names = "--posture", description = "ride-hard or conservative.") String posture;
        @Option(names = "--pause-mode", description = "off, fixed, or smart.") String pauseMode;
        @Option(names = "--fixed-pause-ms", description = "Run-wide throttle pause duration.") Long fixedPauseMillis;
    }

    abstract static class BaseCommand implements Callable<Integer> {
        @Spec CommandSpec spec;
        @Mixin CommonOptions common = new CommonOptions();

        protected YamlJob job() {
            try { return YamlJob.load(common.config); }
            catch (Exception exception) { throw new CommandLine.ParameterException(spec.commandLine(), exception.getMessage(), exception); }
        }

        protected CommonResolved common(YamlJob job, String mode) {
            Path output = first(common.output, job.path("evidence", "output"));
            if (output == null) output = Path.of("bypassfuzzer-output", timestamp() + "-" + mode);
            String protocol = first(common.protocol, job.string("transport", "protocol"), "auto");
            String proxy = first(common.proxy, job.string("transport", "proxy"));
            boolean insecure = first(common.insecure, job.bool("transport", "insecure"), false);
            int timeout = first(common.requestTimeout, job.integer("transport", "requestTimeoutSeconds"), 15);
            int connectTimeout = first(common.connectTimeout, job.integer("transport", "connectTimeoutSeconds"), 10);
            int global = first(common.globalConcurrency, job.integer("execution", "globalConcurrency"),
                ScanDefaults.CONCURRENCY);
            int perHost = first(common.perHostConcurrency, job.integer("execution", "perHostConcurrency"),
                Math.min(ScanDefaults.CONCURRENCY, global));
            int retries = first(common.retryAttempts, job.integer("execution", "retryAttempts"), ScanDefaults.retries(mode));
            int max = first(common.maxProbes, job.integer("execution", "maxProbes"),
                mode.equals("sweep") ? ScanDefaults.SWEEP_PROBES : Integer.MAX_VALUE);
            boolean redact = first(common.redact, job.bool("evidence", "redact"), false);
            List<Integer> throttle = common.throttleCodes != null ? common.throttleCodes : integers(job.strings("execution", "throttleStatusCodes"), List.of(429, 503));
            List<String> headers = common.headers != null ? common.headers : first(job.strings("execution", "headers"), List.of());
            String uaMode = first(common.userAgentMode, job.string("execution", "userAgentMode"), "disabled");
            long uaSeed = first(common.userAgentSeed, job.longValue("execution", "userAgentSeed"), 0L);
            String posture = first(common.posture, job.string("execution", "posture"), "ride-hard");
            String pauseMode = first(common.pauseMode, job.string("execution", "pauseMode"), "off");
            long fixedPause = first(common.fixedPauseMillis, job.longValue("execution", "fixedPauseMillis"), 30_000L);
            ExecutionOptions execution = new ExecutionOptions(output, HttpProtocol.parse(protocol), Duration.ofSeconds(timeout),
                global, perHost, new LinkedHashSet<>(throttle), redact, retries, posture, pauseMode, fixedPause);
            return new CommonResolved(execution, proxy, insecure, connectTimeout, max, headers, uaMode, uaSeed);
        }

        protected int execute(String mode, List<HttpRequestData> requests,
                              Function<HttpRequestData, List<PlannedRequest>> planner,
                              CommonResolved resolved, YamlJob job) {
            return execute(mode, requests, planner, null, resolved, job);
        }

        protected int execute(String mode, List<HttpRequestData> requests,
                              Function<HttpRequestData, List<PlannedRequest>> planner,
                              ScanEngine.PostBaselinePlanner postBaselinePlanner,
                              CommonResolved resolved, YamlJob job) {
            List<HttpRequestData> prepared;
            try { prepare(requests, resolved); prepared = requests; }
            catch (Exception exception) { throw new CommandLine.ParameterException(spec.commandLine(), exception.getMessage(), exception); }
            var policy = headerPolicy(resolved);
            Function<HttpRequestData, List<PlannedRequest>> finalPlanner = base -> {
                var plan = new ArrayList<>(planner.apply(base));
                if (mode.equals("bypass") && plan.stream().noneMatch(PlannedRequest::baseline))
                    plan.add(0, PlannedRequest.baseline(base, "Original request"));
                return plan.stream().map(item -> item.withRequest(policy.reconcileMutation(base, item.request().withSyncedContentLength()))).toList();
            };
            ScanEngine.PostBaselinePlanner finalPostPlanner = postBaselinePlanner == null ? null : (base, authorized, target) ->
                postBaselinePlanner.plan(base, authorized, target).stream()
                    .map(item -> item.withRequest(policy.reconcileMutation(base, item.request().withSyncedContentLength()))).toList();
            if (common.preview) {
                if (this instanceof Sweep sweep && first(sweep.retryPackage, job.path("input", "retryPackage")) != null) {
                    try {
                        for (var entry : loader().retryEntries(first(sweep.retryPackage, job.path("input", "retryPackage")))) {
                            var item = entry.planned();
                            System.out.printf("=== %s ===%n%s%n", item.payload(), policy.reconcileMutation(item.request(), item.request()).toRaw());
                        }
                    } catch (Exception error) { throw inputError(error); }
                    return 0;
                }
                for (var base : prepared) for (var item : finalPlanner.apply(base))
                    System.out.printf("=== %s ===%n%s%n", item.payload(), item.request().toRaw());
                return 0;
            }
            String runId = timestamp() + "-" + UUID.randomUUID().toString().substring(0, 8);
            Map<String, Object> effective = new LinkedHashMap<>(job.effective());
            effective.put("mode", mode);
            effective.put("inputCount", prepared.size());
            effective.put("transport", Map.of(
                "protocol", resolved.options.protocol().id(),
                "proxy", resolved.proxy == null ? "" : resolved.proxy,
                "insecure", resolved.insecure,
                "connectTimeoutSeconds", resolved.connectTimeout,
                "requestTimeoutSeconds", resolved.options.requestTimeout().toSeconds()));
            effective.put("execution", Map.ofEntries(
                Map.entry("globalConcurrency", resolved.options.globalConcurrency()),
                Map.entry("perHostConcurrency", resolved.options.perHostConcurrency()),
                Map.entry("throttleStatusCodes", resolved.options.throttleStatusCodes()),
                Map.entry("retryAttempts", resolved.options.retryAttempts()),
                Map.entry("maxProbes", mode.equals("idor") ? "unlimited" : resolved.maxProbes),
                Map.entry("headers", resolved.headers),
                Map.entry("userAgentMode", resolved.userAgentMode),
                Map.entry("userAgentSeed", resolved.userAgentSeed),
                Map.entry("posture", resolved.options.posture()),
                Map.entry("pauseMode", resolved.options.pauseMode()),
                Map.entry("fixedPauseMillis", resolved.options.fixedPauseMillis())));
            effective.put("evidence", Map.of(
                "output", resolved.options.outputDirectory().toString(),
                "redact", resolved.options.redact()));
            try (EvidenceWriter evidence = new EvidenceWriter(resolved.options.outputDirectory(), runId, resolved.options.redact(), effective);
                 NettyRequestTransport network = new NettyRequestTransport(resolved.insecure, resolved.proxy, Duration.ofSeconds(resolved.connectTimeout));
                 com.bypassfuzzer.cli.run.RunControl control = new com.bypassfuzzer.cli.run.RunControl(
                     first(common.controlFile, job.path("execution", "controlFile")),
                     first(common.trafficMaxInFlight, job.integer("execution", "trafficMaxInFlight")),
                     first(common.trafficMaxRps, job.doubleValue("execution", "trafficMaxRps")))) {
                var transport = control.transport(network);
                try {
                    if (this instanceof Sweep sweep) {
                        Path retry = first(sweep.retryPackage, job.path("input", "retryPackage"));
                        if (retry != null) new ScanExecutor().replay(loader().retryEntries(retry), transport,
                            resolved.options, policy, evidence, control);
                        else new com.bypassfuzzer.cli.run.SweepExecutor().run(prepared, finalPlanner,
                            transport, resolved.options, sweep.workflowOptions(job), policy, evidence, control);
                    } else new ScanExecutor().run(mode, prepared, finalPlanner, finalPostPlanner,
                        transport, resolved.options, evidence, control);
                } catch (Throwable error) {
                    Map<String, Object> failed = new LinkedHashMap<>();
                    failed.put("schemaVersion", 1); failed.put("state", "failed"); failed.put("mode", mode);
                    failed.put("finishedAt", Instant.now().toString()); failed.put("records", evidence.count());
                    failed.put("error", error.getClass().getSimpleName() + ": " + (error.getMessage() == null ? "" : error.getMessage()));
                    evidence.summary(failed);
                    System.err.println("Run failed after start; see summary.json: " + error.getMessage());
                }
                return 0;
            } catch (Exception exception) {
                throw new CommandLine.ParameterException(spec.commandLine(), "Unable to start scan: " + exception.getMessage(), exception);
            }
        }

        protected RequestHeaderPolicy<HttpRequestData> headerPolicy(CommonResolved resolved) {
            UserAgentMode mode = UserAgentMode.valueOf(resolved.userAgentMode.replace('-', '_').toUpperCase(Locale.ROOT));
            return new RequestHeaderPolicy<>(RequestAccess.CORE,
                ConfiguredHeaderParser.parse(String.join("\n", resolved.headers)), mode, resolved.userAgentSeed);
        }

        protected List<HttpRequestData> prepare(List<HttpRequestData> requests, CommonResolved resolved) {
            var policy = headerPolicy(resolved);
            return requests.stream().map(policy::applyToBase).toList();
        }

        protected java.util.function.Supplier<String> outOfBand(YamlJob job) {
            return OutOfBandSource.configured(first(common.oobDomain, job.string("execution", "oobDomain")),
                first(common.oobGenerator, job.path("execution", "oobGenerator")));
        }

        protected CliRequestLoader loader() { return new CliRequestLoader(); }
        protected CommandLine.ParameterException inputError(Exception exception) { return new CommandLine.ParameterException(spec.commandLine(), exception.getMessage(), exception); }

    }

    @Command(name = "sweep", mixinStandardHelpOptions = true, description = "Run Coverage Sweep from URLs, requests, API files, or retry packages.")
    static final class Sweep extends BaseCommand {
        @Option(names = "--urls") Path urls;
        @Option(names = "--request") Path request;
        @Option(names = "--target-origin") String targetOrigin;
        @Option(names = "--request-manifest") Path requestManifest;
        @Option(names = "--openapi") String openapi;
        @Option(names = "--openapi-parameter-policy", description = "source-values-only, required-empty, required-variables (default), all-empty, all-variables, or sample-values.") String openapiParameterPolicy;
        @Option(names = "--openapi-variable", paramLabel = "NAME=VALUE", description = "Managed OpenAPI variable; repeatable, overrides the matching YAML variable.") List<String> openapiVariables;
        @Option(names = "--openapi-fill-examples", negatable = true, description = "Fill empty OpenAPI variables from unambiguous spec examples/defaults or generated suggestions.") Boolean openapiFillExamples;
        @Option(names = "--postman") Path postman;
        @Option(names = "--retry-package") Path retryPackage;
        @Option(names = "--base-url") String baseUrl;
        @Option(names = "--include-state-changing", description = "Include POST/PUT/PATCH/DELETE API operations.") Boolean includeStateChanging;
        @Option(names = "--sweep-mode", description = "blocked, authenticated, or imported.") String sweepMode;
        @Option(names = "--auth-header", description = "Authentication header to strip; repeatable.") List<String> authHeaders;
        @Option(names = "--auth-cookie", description = "Authentication cookie to strip; repeatable.") List<String> authCookies;
        @Option(names = "--verify-unauthenticated-access", negatable = true) Boolean verifyUnauthenticated;
        @Option(names = "--skip-likely-public", negatable = true) Boolean skipPublic;
        @Option(names = "--host-ports", split = ",", description = "Additional Host parsing ports; 0 enables built-in double-port probes.") List<Integer> hostPorts;
        @Option(names = "--max-candidates") Integer maxCandidates;
        @Option(names = "--dedupe-endpoints", negatable = true) Boolean dedupe;
        @Option(names = "--exclude-static-assets", negatable = true) Boolean excludeStaticAssets;
        @Option(names = "--exclude-host", description = "Excluded destination hostname; repeatable.") List<String> excludedHosts;
        @Option(names = "--payload-set", description = "high-signal or all (uncapped full Burp catalog).") String payloadSet;
        @Option(names = "--families", split = ",") List<String> families;

        @Override public Integer call() {
            YamlJob job = job(); CommonResolved common = common(job, "sweep");
            try {
                boolean unsafe = first(includeStateChanging, job.bool("execution", "includeStateChanging"), false);
                var workflow = workflowOptions(job);
                boolean staticAssets = first(excludeStaticAssets, job.bool("sweep", "excludeStaticAssets"), true);
                int candidates = first(maxCandidates, job.integer("sweep", "maxCandidates"), ScanDefaults.SWEEP_CANDIDATES);
                if (candidates < 1) throw new IllegalArgumentException("max-candidates must be positive");
                Set<String> excluded = new LinkedHashSet<>(first(excludedHosts, job.strings("sweep", "excludeHosts"), List.of()));
                boolean replay = first(retryPackage, job.path("input", "retryPackage")) != null;
                List<HttpRequestData> inputs = sweepInputs(job, unsafe).stream()
                    .filter(r -> replay || excluded.stream().noneMatch(h -> h.equalsIgnoreCase(r.origin().host())))
                    .filter(r -> replay || !staticAssets || !com.bypassfuzzer.core.scan.SweepCandidateRules.staticAsset(r.rawTarget(), ""))
                    .filter(r -> replay || !workflow.authenticated() || unsafe || Set.of("GET", "HEAD", "OPTIONS").contains(r.method().toUpperCase(Locale.ROOT)))
                    .toList();
                if (!replay) inputs = com.bypassfuzzer.core.scan.SweepCandidateRules.select(inputs, candidates,
                    first(dedupe, job.bool("sweep", "dedupeEndpoints"), true));
                if (inputs.isEmpty()) throw new IllegalArgumentException("No candidates match the Sweep configuration");
                PayloadSet set = PayloadSet.parse(first(payloadSet, job.string("sweep", "payloadSet"), "high-signal"));
                if (!replay && set == PayloadSet.ALL && (this.common.maxProbes != null || job.integer("execution", "maxProbes") != null))
                    throw new IllegalArgumentException("Sweep all payloads is uncapped, like Burp. Remove --max-probes/execution.maxProbes or choose high-signal/selected families.");
                List<String> configuredFamilies = families != null ? families : job.strings("sweep", "families");
                Function<HttpRequestData, List<PlannedRequest>> planner;
                if (set == PayloadSet.HIGH_SIGNAL) {
                    Set<String> selected = configuredFamilies == null ? HighSignalPlanner.FAMILIES : new LinkedHashSet<>(configuredFamilies);
                    for (String family : selected) if (!HighSignalPlanner.FAMILIES.contains(family)) throw new IllegalArgumentException("Unknown high-signal family: " + family);
                    List<Integer> ports = hostPorts != null ? hostPorts : integers(job.strings("sweep", "hostPorts"), List.of(0));
                    for (int port : ports) if (port < 0 || port > 65535) throw new IllegalArgumentException("Host port must be between 0 and 65535");
                    planner = value -> new SweepPlanner().highSignal(value, selected, common.maxProbes, ports, !workflow.authenticated());
                } else {
                    Set<AttackFamily> selected = attackFamilies(configuredFamilies);
                    var domain = outOfBand(job);
                    planner = value -> new SweepPlanner().all(value, selected, domain, !workflow.authenticated());
                }
                return execute("sweep", inputs, planner, common, job);
            } catch (Exception exception) { throw inputError(exception); }
        }

        com.bypassfuzzer.core.scan.SweepWorkflow.Options workflowOptions(YamlJob job) {
            String mode = first(sweepMode, job.string("sweep", "mode"), "blocked").toLowerCase(Locale.ROOT);
            if (!Set.of("blocked", "authenticated", "imported").contains(mode))
                throw new IllegalArgumentException("Sweep mode must be blocked, authenticated, or imported");
            return new com.bypassfuzzer.core.scan.SweepWorkflow.Options(mode.equals("authenticated"),
                first(verifyUnauthenticated, job.bool("sweep", "verifyUnauthenticatedAccess"), true),
                first(skipPublic, job.bool("sweep", "skipLikelyPublicEndpoints"), true),
                new LinkedHashSet<>(first(authHeaders, job.strings("sweep", "authHeaders"), List.of("Authorization"))),
                new LinkedHashSet<>(first(authCookies, job.strings("sweep", "authCookies"), List.of())));
        }

        private List<HttpRequestData> sweepInputs(YamlJob job, boolean unsafe) throws Exception {
            Path urls = first(this.urls, job.path("input", "urls"));
            Path request = first(this.request, job.path("input", "request"));
            String origin = first(targetOrigin, job.string("input", "targetOrigin"));
            Path manifest = first(requestManifest, job.path("input", "requestManifest"));
            String openapi = first(this.openapi, job.location("input", "openapi"));
            Path postman = first(this.postman, job.path("input", "postman"));
            Path retry = first(retryPackage, job.path("input", "retryPackage"));
            String base = first(baseUrl, job.string("input", "baseUrl"));
            int sources = bool(urls) + bool(request) + bool(manifest) + bool(openapi) + bool(postman) + bool(retry);
            if (sources != 1) throw new IllegalArgumentException("Sweep requires exactly one input source");
            if (openapi == null && (openapiParameterPolicy != null || openapiVariables != null
                || openapiFillExamples != null || job.string("input", "openapiParameterPolicy") != null
                || job.bool("input", "openapiFillExamples") != null || !job.stringValues("input", "openapiVariables").isEmpty()))
                throw new IllegalArgumentException("OpenAPI parameter controls require --openapi or input.openapi");
            if (urls != null) return loader().urls(urls, unsafe);
            if (request != null) return loader().raw(request, origin);
            if (manifest != null) return loader().manifest(manifest);
            if (openapi != null) return loader().openApi(openapi, base, unsafe, openApiOptions(job),
                first(openapiFillExamples, job.bool("input", "openapiFillExamples"), false));
            if (postman != null) return loader().postman(postman, base, unsafe);
            return loader().retryPackage(retry);
        }

        private OpenApiImportOptions openApiOptions(YamlJob job) {
            String policy = first(openapiParameterPolicy, job.string("input", "openapiParameterPolicy"), "required-variables");
            OpenApiImportOptions.ParameterPolicy selected;
            try {
                selected = OpenApiImportOptions.ParameterPolicy.valueOf(policy.trim().replace('-', '_').toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException error) {
                throw new IllegalArgumentException("Unknown OpenAPI parameter policy: " + policy);
            }
            Map<String, String> variables = new LinkedHashMap<>(job.stringValues("input", "openapiVariables"));
            if (openapiVariables != null) for (String assignment : openapiVariables) {
                int separator = assignment.indexOf('=');
                if (separator <= 0 || assignment.substring(0, separator).trim().isEmpty())
                    throw new IllegalArgumentException("Each OpenAPI variable needs a NAME=VALUE entry");
                variables.put(assignment.substring(0, separator).trim(), assignment.substring(separator + 1));
            }
            return new OpenApiImportOptions(selected, variables);
        }
    }

    @Command(name = "bypass", mixinStandardHelpOptions = true, description = "Run targeted authorization-bypass attack families.")
    static final class Bypass extends BaseCommand {
        @Option(names = "--request") Path request;
        @Option(names = "--target-origin") String targetOrigin;
        @Option(names = "--families", split = ",") List<String> families;
        @Option(names = "--fuzz-existing-cookies", negatable = true) Boolean fuzzExistingCookies;
        @Override public Integer call() {
            YamlJob job = job(); CommonResolved common = common(job, "bypass");
            try {
                List<HttpRequestData> input = loader().raw(first(request, job.path("input", "request")), first(targetOrigin, job.string("input", "targetOrigin")));
                Set<AttackFamily> selected = attackFamilies(families != null ? families : job.strings("bypass", "families"));
                boolean fuzzCookies = first(fuzzExistingCookies, job.bool("bypass", "fuzzExistingCookies"), true);
                var domains = outOfBand(job);
                return execute("bypass", input, value -> new BypassPlanner(domains).plan(value, selected, fuzzCookies, common.maxProbes), common, job);
            } catch (Exception exception) { throw inputError(exception); }
        }
    }

    @Command(name = "idor", mixinStandardHelpOptions = true, description = "Run IDOR/BOLA baselines and registered playbooks.")
    static final class Idor extends BaseCommand {
        @Option(names = "--request") Path request;
        @Option(names = "--target-origin") String targetOrigin;
        @Option(names = "--authorized-id") String authorizedId;
        @Option(names = "--target-id") String targetId;
        @Option(names = "--id-location", description = "Exact discovered ID slot, e.g. path:5, json:/account/id, header:x-object-id#0, or multipart:id#0.") String location;
        @Option(names = "--families", split = ",", description = "Selected IDOR playbook IDs.") List<String> families;
        @Option(names = "--include-method-changes", description = "Include method and override variants.") Boolean includeMethodChanges;
        @Option(names = "--unique-json-field", description = "JSON pointer to a string field given a unique value per request, e.g. /name.") String uniqueJsonField;
        @Option(names = "--baseline-response", description = "Saved raw HTTP response for offline response-guided preview.") Path baselineResponse;
        @Override public Integer call() {
            YamlJob job = job(); CommonResolved common = common(job, "idor");
            try {
                if (this.common.maxProbes != null || job.integer("execution", "maxProbes") != null)
                    throw new IllegalArgumentException("IDOR no longer supports --max-probes or execution.maxProbes; all enabled playbook probes are planned.");
                List<HttpRequestData> input = loader().raw(first(request, job.path("input", "request")), first(targetOrigin, job.string("input", "targetOrigin")));
                String authorized = first(authorizedId, job.string("idor", "authorizedId"));
                String target = first(targetId, job.string("idor", "targetId"));
                String selectedLocation = first(location, job.string("idor", "location"));
                List<String> selectedFamilies = first(families, job.strings("idor", "families"), List.of());
                boolean methods = first(includeMethodChanges, job.bool("idor", "includeMethodChanges"), false);
                IdorPlanOptions idor = new IdorPlanOptions(authorized, target, selectedLocation,
                    new LinkedHashSet<>(selectedFamilies), IdorPlanOptions.UNLIMITED, methods,
                    first(uniqueJsonField, job.string("idor", "uniqueJsonField")),
                    UUID.randomUUID().toString().substring(0, 8));
                IdorPlanner idorPlanner = new IdorPlanner();
                for (String family : idorPlanner.availableFamilies())
                    if (idor.families().contains(family)
                        && idorPlanner.dangerousFamilyRisks().containsKey(family))
                        System.err.println("DANGEROUS: " + family + ": "
                            + idorPlanner.dangerousFamilyRisks().get(family));
                prepare(input, common);
                List<HttpRequestData> prepared = input;
                ResponseGuidedIdorPlanner guided = new ResponseGuidedIdorPlanner();
                HttpResponseData sample = null;
                Path responseFile = first(baselineResponse, job.path("idor", "baselineResponse"));
                if (responseFile != null) sample = new RawHttpResponseParser().parse(Files.readAllBytes(responseFile));
                HttpRequestData previewRequest = prepared.get(0).withProtocol(common.options.protocol());
                List<PlannedRequest> firstPlan = guided.enabled(idor)
                    ? guided.plan(previewRequest, idor, sample, null)
                    : new IdorPlanner().plan(previewRequest, idor);
                if (this.common.preview) {
                    for (PlannedRequest planned : firstPlan)
                        System.out.printf("=== %s ===%n%s%n", planned.payload(),
                            headerPolicy(common).reconcileMutation(previewRequest, planned.request()).toRaw());
                    var coverage = idorPlanner.separatorCoverage(previewRequest, idor, firstPlan);
                    if (coverage != null) {
                        System.err.println("Paired control separators: " + coverage.planned()
                            + "/" + coverage.eligible() + " planned");
                        coverage.notes().forEach(System.err::println);
                    }
                    if (guided.enabled(idor) && sample == null)
                        System.err.println("Response-guided probes require live baselines or --baseline-response for offline preview.");
                    return 0;
                }
                if (guided.enabled(idor)) return execute("idor", input,
                    value -> guided.initialPlan(value, idor),
                    (value, authorizedResponse, targetResponse) -> guided.plan(value, idor,
                        authorizedResponse, targetResponse), common, job);
                return execute("idor", input, value -> new IdorPlanner().plan(value, idor), common, job);
            } catch (Exception exception) { throw inputError(exception); }
        }
    }

    @Command(name = "url-validation", mixinStandardHelpOptions = true, description = "Run marker-based URL parser and allow-list validation payloads.")
    static final class UrlValidation extends BaseCommand {
        @Option(names = "--request") Path request;
        @Option(names = "--target-origin") String targetOrigin;
        @Option(names = "--marker") String marker;
        @Option(names = "--allowed-host") String allowedHost;
        @Option(names = "--attacker-host") String attackerHost;
        @Option(names = "--scheme") String scheme;
        @Option(names = "--contexts", split = ",") List<String> contexts;
        @Option(names = "--attacks", split = ",") List<String> attacks;
        @Option(names = "--encodings", split = ",") List<String> encodings;
        @Override public Integer call() {
            YamlJob job = job(); CommonResolved common = common(job, "url-validation");
            try {
                List<HttpRequestData> input = loader().raw(first(request, job.path("input", "request")), first(targetOrigin, job.string("input", "targetOrigin")));
                String destination = first(attackerHost, job.string("urlValidation", "attackerHost"));
                if (destination == null || destination.isBlank()) destination = outOfBand(job).get();
                UrlValidationOptions options = new UrlValidationOptions(
                    first(marker, job.string("urlValidation", "marker"), "{INJECT}"),
                    first(allowedHost, job.string("urlValidation", "allowedHost"), ""),
                    destination,
                    first(scheme, job.string("urlValidation", "scheme"), "https"),
                    enumSet(contexts != null ? contexts : job.strings("urlValidation", "contexts"), UrlValidationContext.class),
                    enumSet(attacks != null ? attacks : job.strings("urlValidation", "attacks"), UrlValidationAttackSetting.class),
                    enumSet(encodings != null ? encodings : job.strings("urlValidation", "encodings"), UrlValidationEncoding.class));
                for (var value : input) new UrlValidationPlanner().validate(value, options);
                return execute("url-validation", input, value -> new UrlValidationPlanner().plan(value, options, common.maxProbes), common, job);
            } catch (Exception exception) { throw inputError(exception); }
        }
    }

    record CommonResolved(ExecutionOptions options, String proxy, boolean insecure, int connectTimeout, int maxProbes,
                          List<String> headers, String userAgentMode, long userAgentSeed) {}

    private static Set<AttackFamily> attackFamilies(List<String> values) { if (values == null || values.isEmpty()) return new LinkedHashSet<>(Arrays.asList(AttackFamily.values())); Set<AttackFamily> output = new LinkedHashSet<>(); values.forEach(value -> output.add(AttackFamily.parse(value))); return output; }
    private static <E extends Enum<E>> Set<E> enumSet(List<String> values, Class<E> type) { if (values == null || values.isEmpty()) return null; Set<E> output = new LinkedHashSet<>(); for (String value : values) { String normalized = value.trim().replace('-', '_').replace(' ', '_').toUpperCase(Locale.ROOT); if (type == UrlValidationContext.class) { if (normalized.equals("HOST_HEADER")) normalized = "HOSTNAME"; if (normalized.equals("CORS")) normalized = "CORS_ORIGIN"; } output.add(Enum.valueOf(type, normalized)); } return output; }
    private static List<Integer> integers(List<String> values, List<Integer> fallback) { if (values == null) return fallback; return values.stream().map(String::trim).filter(value -> !value.isEmpty()).map(Integer::valueOf).toList(); }
    private static int bool(Object value) { return value == null ? 0 : 1; }
    @SafeVarargs private static <T> T first(T... values) { for (T value : values) if (value != null) return value; return null; }
    private static String timestamp() { return DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC).format(Instant.now()); }
}

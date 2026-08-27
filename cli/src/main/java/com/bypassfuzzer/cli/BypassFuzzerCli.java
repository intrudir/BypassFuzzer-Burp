package com.bypassfuzzer.cli;

import com.bypassfuzzer.cli.config.YamlJob;
import com.bypassfuzzer.cli.evidence.EvidenceWriter;
import com.bypassfuzzer.cli.input.CliRequestLoader;
import com.bypassfuzzer.cli.run.ExecutionOptions;
import com.bypassfuzzer.cli.run.ScanExecutor;
import com.bypassfuzzer.cli.transport.NettyRequestTransport;
import com.bypassfuzzer.core.http.HttpProtocol;
import com.bypassfuzzer.core.http.HttpRequestData;
import com.bypassfuzzer.core.scan.AttackFamily;
import com.bypassfuzzer.core.scan.BypassPlanner;
import com.bypassfuzzer.core.scan.HighSignalPlanner;
import com.bypassfuzzer.core.scan.IdorPlanner;
import com.bypassfuzzer.core.scan.PayloadSet;
import com.bypassfuzzer.core.scan.PlannedRequest;
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
        BypassFuzzerCli.Idor.class, BypassFuzzerCli.UrlValidation.class})
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
        @Option(names = "--max-probes", description = "Maximum mutations generated per input.") Integer maxProbes;
        @Option(names = "--redact", description = "Redact common credential headers in stored evidence.") Boolean redact;
        @Option(names = "--header", description = "Upsert a header on every base request; repeatable.") List<String> headers;
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
            int global = first(common.globalConcurrency, job.integer("execution", "globalConcurrency"), 10);
            int perHost = first(common.perHostConcurrency, job.integer("execution", "perHostConcurrency"), Math.min(10, global));
            int retries = first(common.retryAttempts, job.integer("execution", "retryAttempts"), 1);
            int max = first(common.maxProbes, job.integer("execution", "maxProbes"), mode.equals("sweep") ? 80 : 2_000);
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
            List<HttpRequestData> prepared;
            try { prepared = prepare(requests, resolved); }
            catch (Exception exception) { throw new CommandLine.ParameterException(spec.commandLine(), exception.getMessage(), exception); }
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
                Map.entry("maxProbes", resolved.maxProbes),
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
                 NettyRequestTransport transport = new NettyRequestTransport(resolved.insecure, resolved.proxy, Duration.ofSeconds(resolved.connectTimeout))) {
                try {
                    new ScanExecutor().run(mode, prepared, planner, transport, resolved.options, evidence);
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

        private List<HttpRequestData> prepare(List<HttpRequestData> requests, CommonResolved resolved) {
            List<HttpRequestData> output = new ArrayList<>();
            int sequence = 0;
            for (HttpRequestData original : requests) {
                HttpRequestData request = original;
                for (String header : resolved.headers) {
                    int colon = header.indexOf(':');
                    if (colon <= 0) throw new IllegalArgumentException("Header must use Name: value syntax: " + header);
                    request = request.upsertHeader(header.substring(0, colon).trim(), header.substring(colon + 1).trim());
                }
                String mode = resolved.userAgentMode.toLowerCase(Locale.ROOT);
                if (!(mode.equals("disabled") || mode.equals("synthetic") || mode.equals("browser-like"))) {
                    throw new IllegalArgumentException("Unknown User-Agent mode: " + mode);
                }
                if (!mode.equals("disabled")) {
                    String userAgent = mode.equals("synthetic")
                        ? "vexa-" + Long.toUnsignedString(resolved.userAgentSeed + sequence, 36) + " orbit-cli"
                        : browserUserAgent(sequence);
                    request = request.upsertHeader("User-Agent", userAgent);
                }
                output.add(request);
                sequence++;
            }
            return List.copyOf(output);
        }

        protected CliRequestLoader loader() { return new CliRequestLoader(); }
        protected CommandLine.ParameterException inputError(Exception exception) { return new CommandLine.ParameterException(spec.commandLine(), exception.getMessage(), exception); }
        private String browserUserAgent(int sequence) { return sequence % 2 == 0 ? "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126 Safari/537.36" : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17 Safari/605.1.15"; }
    }

    @Command(name = "sweep", mixinStandardHelpOptions = true, description = "Run Coverage Sweep from URLs, requests, API files, or retry packages.")
    static final class Sweep extends BaseCommand {
        @Option(names = "--urls") Path urls;
        @Option(names = "--request") Path request;
        @Option(names = "--target-origin") String targetOrigin;
        @Option(names = "--request-manifest") Path requestManifest;
        @Option(names = "--openapi") String openapi;
        @Option(names = "--postman") Path postman;
        @Option(names = "--retry-package") Path retryPackage;
        @Option(names = "--base-url") String baseUrl;
        @Option(names = "--include-state-changing", description = "Include POST/PUT/PATCH/DELETE API operations.") Boolean includeStateChanging;
        @Option(names = "--payload-set", description = "high-signal or all.") String payloadSet;
        @Option(names = "--families", split = ",") List<String> families;

        @Override public Integer call() {
            YamlJob job = job(); CommonResolved common = common(job, "sweep");
            try {
                boolean unsafe = first(includeStateChanging, job.bool("execution", "includeStateChanging"), false);
                List<HttpRequestData> inputs = sweepInputs(job, unsafe);
                PayloadSet set = PayloadSet.parse(first(payloadSet, job.string("sweep", "payloadSet"), "high-signal"));
                List<String> configuredFamilies = families != null ? families : job.strings("sweep", "families");
                Function<HttpRequestData, List<PlannedRequest>> planner;
                if (set == PayloadSet.HIGH_SIGNAL) {
                    Set<String> selected = configuredFamilies == null ? HighSignalPlanner.FAMILIES : new LinkedHashSet<>(configuredFamilies);
                    for (String family : selected) if (!HighSignalPlanner.FAMILIES.contains(family)) throw new IllegalArgumentException("Unknown high-signal family: " + family);
                    planner = value -> new HighSignalPlanner().plan(value, selected, common.maxProbes);
                } else {
                    Set<AttackFamily> selected = attackFamilies(configuredFamilies);
                    planner = value -> new BypassPlanner().plan(value, selected, false, common.maxProbes);
                }
                return execute("sweep", inputs, planner, common, job);
            } catch (Exception exception) { throw inputError(exception); }
        }

        private List<HttpRequestData> sweepInputs(YamlJob job, boolean unsafe) throws Exception {
            Path urls = first(this.urls, job.path("input", "urls"));
            Path request = first(this.request, job.path("input", "request"));
            String origin = first(targetOrigin, job.string("input", "targetOrigin"));
            Path manifest = first(requestManifest, job.path("input", "requestManifest"));
            String openapi = first(this.openapi, job.string("input", "openapi"));
            Path postman = first(this.postman, job.path("input", "postman"));
            Path retry = first(retryPackage, job.path("input", "retryPackage"));
            String base = first(baseUrl, job.string("input", "baseUrl"));
            int sources = bool(urls) + bool(request) + bool(manifest) + bool(openapi) + bool(postman) + bool(retry);
            if (sources != 1) throw new IllegalArgumentException("Sweep requires exactly one input source");
            if (urls != null) return loader().urls(urls, unsafe);
            if (request != null) return loader().raw(request, origin);
            if (manifest != null) return loader().manifest(manifest);
            if (openapi != null) return loader().openApi(openapi, base, unsafe);
            if (postman != null) return loader().postman(postman, base, unsafe);
            return loader().retryPackage(retry);
        }
    }

    @Command(name = "bypass", mixinStandardHelpOptions = true, description = "Run targeted authorization-bypass attack families.")
    static final class Bypass extends BaseCommand {
        @Option(names = "--request") Path request;
        @Option(names = "--target-origin") String targetOrigin;
        @Option(names = "--families", split = ",") List<String> families;
        @Option(names = "--fuzz-existing-cookies") Boolean fuzzExistingCookies;
        @Override public Integer call() {
            YamlJob job = job(); CommonResolved common = common(job, "bypass");
            try {
                List<HttpRequestData> input = loader().raw(first(request, job.path("input", "request")), first(targetOrigin, job.string("input", "targetOrigin")));
                Set<AttackFamily> selected = attackFamilies(families != null ? families : job.strings("bypass", "families"));
                boolean fuzzCookies = first(fuzzExistingCookies, job.bool("bypass", "fuzzExistingCookies"), false);
                return execute("bypass", input, value -> new BypassPlanner().plan(value, selected, fuzzCookies, common.maxProbes), common, job);
            } catch (Exception exception) { throw inputError(exception); }
        }
    }

    @Command(name = "idor", mixinStandardHelpOptions = true, description = "Run IDOR/BOLA baselines and registered playbooks.")
    static final class Idor extends BaseCommand {
        @Option(names = "--request") Path request;
        @Option(names = "--target-origin") String targetOrigin;
        @Option(names = "--authorized-id") String authorizedId;
        @Option(names = "--target-id") String targetId;
        @Override public Integer call() {
            YamlJob job = job(); CommonResolved common = common(job, "idor");
            try {
                List<HttpRequestData> input = loader().raw(first(request, job.path("input", "request")), first(targetOrigin, job.string("input", "targetOrigin")));
                String authorized = first(authorizedId, job.string("idor", "authorizedId"));
                String target = first(targetId, job.string("idor", "targetId"));
                return execute("idor", input, value -> new IdorPlanner().plan(value, authorized, target, common.maxProbes), common, job);
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
                UrlValidationOptions options = new UrlValidationOptions(
                    first(marker, job.string("urlValidation", "marker"), "{INJECT}"),
                    first(allowedHost, job.string("urlValidation", "allowedHost"), ""),
                    first(attackerHost, job.string("urlValidation", "attackerHost")),
                    first(scheme, job.string("urlValidation", "scheme"), "https"),
                    enumSet(contexts != null ? contexts : job.strings("urlValidation", "contexts"), UrlValidationContext.class),
                    enumSet(attacks != null ? attacks : job.strings("urlValidation", "attacks"), UrlValidationAttackSetting.class),
                    enumSet(encodings != null ? encodings : job.strings("urlValidation", "encodings"), UrlValidationEncoding.class));
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

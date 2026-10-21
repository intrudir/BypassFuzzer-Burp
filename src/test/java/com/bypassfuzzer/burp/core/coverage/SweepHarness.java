package com.bypassfuzzer.burp.core.coverage;
import com.bypassfuzzer.core.throttle.ThrottleSettings;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.core.http.ConfiguredHeader;
import com.bypassfuzzer.burp.http.RequestSender;
import com.bypassfuzzer.burp.smoke.MontoyaStubs;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Live-fire harness that runs the <em>real</em> Coverage Sweep pipeline against a URL list: the
 * production {@link CoverageSweepEngine} + {@link CoverageSweepProbeGenerator} generate the actual
 * mutated bypass probes per endpoint, and {@code engine.start(...)} builds the real adaptive
 * {@link com.bypassfuzzer.burp.core.throttle.HostThrottleCoordinator} and fires them concurrently
 * across every host — exactly as sweep mode does in Burp. The only substitution is transport: a
 * {@link java.net.http.HttpClient}-backed {@link RequestSender} instead of Burp's Montoya sender,
 * with request/response wrapped as Montoya objects via {@code MontoyaStubs} so the engine sees its
 * normal interface.
 *
 * <p>Not a JUnit test (has {@code main}, no {@code @Test}). Run (resources dir is needed for the
 * probe wordlist, montoya-api + mockito for the stubs):</p>
 * <pre>
 *   java -Djdk.httpclient.allowRestrictedHeaders=host,connection,content-length \
 *        -cp "build/classes/java/test;build/classes/java/main;build/resources/main;&lt;montoya&gt;;&lt;mockito&gt;;&lt;byte-buddy&gt;;&lt;objenesis&gt;" \
 *        com.bypassfuzzer.burp.core.coverage.SweepHarness \
 *        C:/Users/jonat/Downloads/bf_me.txt --per-host-candidates 1 --max-probes 80 --payloads high --insecure
 * </pre>
 *
 * <p><b>Sends real, mutated HTTP requests to every host in the list.</b> Authorised targets only.</p>
 */
public final class SweepHarness {

    private static final String BROWSER_UA =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
            + "Chrome/126.0.0.0 Safari/537.36";

    public static void main(String[] args) throws Exception {
        Config config = parse(args);
        List<String> allUrls = loadUrls(config.listFile());
        List<String> urls = limitHosts(pickPerHost(allUrls, config.perHostCandidates()), config.maxHosts());
        System.out.printf("Imported %d of %d URLs (%d per host) across %d hosts. payloads=%s, maxProbes=%d, "
                + "global=%d, per-host=%d%n",
            urls.size(), allUrls.size(), config.perHostCandidates(), distinctHosts(urls),
            config.payloadSet(), config.maxProbes(), config.globalConcurrency(), config.perHostConcurrency());

        HttpClient client = buildClient(config);
        NetworkRequestSender sender = new NetworkRequestSender(client, config.insecure());

        CoverageSweepOptions options = new CoverageSweepOptions(
            Set.of(401, 403), false, urls.size(), config.maxProbes(),
            config.globalConcurrency(), config.perHostConcurrency(), Set.of(429, 503),
            CoverageSweepMode.IMPORTED_TARGETS, CoverageSweepAuthSelection.defaults(), true, false,
            List.of(), List.of(new ConfiguredHeader("User-Agent", BROWSER_UA)), config.payloadSet(),
            com.bypassfuzzer.core.throttle.ThrottleSettings.Posture.RIDE_HARD);

        CoverageSweepEngine engine = new CoverageSweepEngine(
            stubApi(), sender, new CoverageSweepProbeGenerator(), SweepHarness::importedRequest);

        CoverageSweepPreview preview = engine.collectPreviewFromUrls(urls, options);
        List<CoverageSweepCandidate> candidates = preview.candidates();
        System.out.printf("Built %d sweep candidates; generating + sending real bypass probes...%n%n",
            candidates.size());

        Map<String, HostStats> stats = new ConcurrentHashMap<>();
        Map<Integer, AtomicInteger> codes = new ConcurrentHashMap<>();
        Map<String, AtomicInteger> fingerprints = new ConcurrentHashMap<>();
        AtomicInteger total = new AtomicInteger();
        AtomicInteger consecutiveThrottles = new AtomicInteger();
        AtomicBoolean resumed = new AtomicBoolean();
        Map<Integer, AtomicInteger> postResumeCodes = new ConcurrentHashMap<>();
        long start = System.nanoTime();

        CountDownLatch done = new CountDownLatch(1);
        boolean started = engine.start(candidates, options, result -> {
            record(result, stats, codes, fingerprints, total);
            HttpResponse response = result.getResponse();
            int status = response == null ? -1 : response.statusCode();
            if (status == 429 || status == 503) {
                consecutiveThrottles.incrementAndGet();
            } else {
                consecutiveThrottles.set(0);
            }
            if (resumed.get()) {
                postResumeCodes.computeIfAbsent(status, ignored -> new AtomicInteger()).incrementAndGet();
            }
        }, done::countDown);
        if (!started) {
            System.out.println("Engine did not start (no candidates?).");
            return;
        }

        Thread monitor = monitor(total, stats, start);
        Thread pauseExperiment = pauseExperiment(engine, config, consecutiveThrottles, total, resumed);
        done.await(config.maxSeconds(), TimeUnit.SECONDS);
        engine.stop();
        monitor.interrupt();
        if (pauseExperiment != null) pauseExperiment.interrupt();
        printSummary(stats, codes, fingerprints, sender, start, System.nanoTime());
        if (config.pauseAfterConsecutive() > 0) {
            System.out.println("\nPost-resume response codes: " + new java.util.TreeMap<>(
                toIntMap(postResumeCodes)));
        }
    }

    // -- result recording ----------------------------------------------------

    private static final class HostStats {
        final AtomicInteger sent = new AtomicInteger();
        final AtomicInteger throttled = new AtomicInteger();
        final Map<Integer, AtomicInteger> codes = new ConcurrentHashMap<>();
    }

    private static void record(AttackResult result, Map<String, HostStats> stats,
                               Map<Integer, AtomicInteger> codes, Map<String, AtomicInteger> fingerprints,
                               AtomicInteger total) {
        HttpResponse response = result.getResponse();
        String host = hostOf(result.getRequest());
        HostStats hs = stats.computeIfAbsent(host, h -> new HostStats());
        hs.sent.incrementAndGet();
        total.incrementAndGet();
        int status = response == null ? -1 : response.statusCode();
        codes.computeIfAbsent(status, s -> new AtomicInteger()).incrementAndGet();
        hs.codes.computeIfAbsent(status, s -> new AtomicInteger()).incrementAndGet();
        if (status == 429 || status == 503) {
            hs.throttled.incrementAndGet();
        }
        if (response != null) {
            int len = response.body() == null ? 0 : response.body().length();
            String server = safe(response.headerValue("Server"));
            String ra = safe(response.headerValue("Retry-After"));
            fingerprints.computeIfAbsent(status + " | len=" + len + " | server=" + server + " | retry-after=" + ra,
                s -> new AtomicInteger()).incrementAndGet();
        }
    }

    private static Thread monitor(AtomicInteger total, Map<String, HostStats> stats, long start) {
        Thread t = new Thread(() -> {
            int prevSent = 0;
            int prevThrottled = 0;
            try {
                while (!Thread.currentThread().isInterrupted()) {
                    TimeUnit.SECONDS.sleep(3);
                    double elapsed = (System.nanoTime() - start) / 1e9;
                    int sent = total.get();
                    int throttled = stats.values().stream().mapToInt(h -> h.throttled.get()).sum();
                    int windowSent = sent - prevSent;
                    int windowThrottled = throttled - prevThrottled;
                    // Windowed 429 rate reveals convergence: it should fall as the controller settles.
                    System.out.printf("  [%3.0fs] probes=%d  this window: %d sent, %d throttled (%.1f%%), %.0f req/s%n",
                        elapsed, sent, windowSent, windowThrottled,
                        windowSent == 0 ? 0 : 100.0 * windowThrottled / windowSent,
                        windowSent / 3.0);
                    prevSent = sent;
                    prevThrottled = throttled;
                }
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }, "sweep-harness-monitor");
        t.setDaemon(true);
        t.start();
        return t;
    }

    private static Thread pauseExperiment(CoverageSweepEngine engine, Config config,
                                          AtomicInteger consecutiveThrottles, AtomicInteger total,
                                          AtomicBoolean resumed) {
        if (config.pauseAfterConsecutive() <= 0 || config.pauseSeconds() <= 0) return null;
        Thread thread = new Thread(() -> {
            try {
                while (engine.isRunning()
                    && consecutiveThrottles.get() < config.pauseAfterConsecutive()) {
                    TimeUnit.MILLISECONDS.sleep(100);
                }
                if (!engine.isRunning()) return;
                int beforePause = total.get();
                System.out.printf("%nPAUSE EXPERIMENT: detected %d consecutive throttles at result %d; "
                        + "pausing for %d seconds.%n",
                    consecutiveThrottles.get(), beforePause, config.pauseSeconds());
                engine.pause();
                TimeUnit.SECONDS.sleep(config.pauseSeconds());
                int arrivedDuringPause = total.get() - beforePause;
                System.out.printf("PAUSE EXPERIMENT: %d already-sent response(s) arrived while paused; resuming.%n%n",
                    arrivedDuringPause);
                consecutiveThrottles.set(0);
                resumed.set(true);
                engine.resume();
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }, "sweep-harness-pause-experiment");
        thread.setDaemon(true);
        thread.start();
        return thread;
    }

    private static void printSummary(Map<String, HostStats> stats, Map<Integer, AtomicInteger> codes,
                                     Map<String, AtomicInteger> fingerprints, NetworkRequestSender sender,
                                     long start, long end) {
        System.out.printf("%n%-52s %8s %8s %10s%n", "host", "probes", "429/503", "throttle%");
        int totalSent = 0;
        int totalThrottled = 0;
        List<Map.Entry<String, HostStats>> rows = new ArrayList<>(stats.entrySet());
        rows.sort(Map.Entry.comparingByKey());
        for (Map.Entry<String, HostStats> e : rows) {
            int sent = e.getValue().sent.get();
            int thr = e.getValue().throttled.get();
            totalSent += sent;
            totalThrottled += thr;
            System.out.printf("%-52s %8d %8d %9.1f%%%n", abbreviate(e.getKey(), 52), sent, thr,
                sent == 0 ? 0 : 100.0 * thr / sent);
        }
        double span = (end - start) / 1e9;
        System.out.printf("%n%-52s %8d %8d %9.1f%%   time %.1fs, %.0f req/s, transport errors=%d%n",
            "TOTAL", totalSent, totalThrottled, totalSent == 0 ? 0 : 100.0 * totalThrottled / totalSent,
            span, span > 0 ? totalSent / span : 0, sender.errors.get());
        System.out.println("\nResponse codes (status -> count): " + new java.util.TreeMap<>(
            toIntMap(codes)));
        System.out.println("\nDistinct response fingerprints (most common first):");
        fingerprints.entrySet().stream()
            .sorted((a, b) -> Integer.compare(b.getValue().get(), a.getValue().get()))
            .limit(25)
            .forEach(e -> System.out.printf("  %6d  %s%n", e.getValue().get(), e.getKey()));
    }

    // -- request construction + transport ------------------------------------

    /** Builds the imported base request as a Montoya proxy (mutated later by the probe generator). */
    private static HttpRequest importedRequest(URI uri) {
        boolean secure = "https".equalsIgnoreCase(uri.getScheme());
        int port = uri.getPort() >= 0 ? uri.getPort() : (secure ? 443 : 80);
        String path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
        if (uri.getRawQuery() != null) {
            path += "?" + uri.getRawQuery();
        }
        HttpService service = MontoyaStubs.httpService(uri.getHost(), port, secure);
        String raw = "GET " + path + " HTTP/1.1\r\nHost: " + uri.getHost() + "\r\n\r\n";
        return MontoyaStubs.request(service, raw);
    }

    /** RequestSender that performs the real HTTP round-trip and wraps the reply as a Montoya response. */
    private static final class NetworkRequestSender implements RequestSender {
        private final HttpClient client;
        private final boolean insecure;
        final AtomicInteger errors = new AtomicInteger();

        NetworkRequestSender(HttpClient client, boolean insecure) {
            this.client = client;
            this.insecure = insecure;
        }

        @Override
        public HttpResponse send(HttpRequest request) {
            HttpService service = request.httpService();
            String scheme = service.secure() ? "https" : "http";
            String url = scheme + "://" + service.host() + ":" + service.port() + request.path();
            String body = request.bodyToString() == null ? "" : request.bodyToString();
            try {
                java.net.http.HttpRequest.Builder builder = java.net.http.HttpRequest.newBuilder(URI.create(url))
                    .timeout(Duration.ofSeconds(15))
                    .method(request.method(),
                        body.isEmpty() ? java.net.http.HttpRequest.BodyPublishers.noBody()
                            : java.net.http.HttpRequest.BodyPublishers.ofString(body));
                for (HttpHeader header : request.headers()) {
                    String name = header.name();
                    if (name.equalsIgnoreCase("Content-Length") || name.equalsIgnoreCase("Connection")) {
                        continue; // managed by the client
                    }
                    try {
                        builder.header(name, header.value());
                    } catch (IllegalArgumentException restricted) {
                        // some headers (Host, ...) require -Djdk.httpclient.allowRestrictedHeaders; skip if not allowed
                    }
                }
                var real = client.send(builder.build(), BodyHandlers.ofByteArray());
                return toMontoyaResponse(real);
            } catch (Exception e) {
                errors.incrementAndGet();
                return null;
            }
        }

        @Override
        public HttpResponse send(HttpRequest request, long timeout, TimeUnit timeUnit) {
            return send(request);
        }

        private HttpResponse toMontoyaResponse(java.net.http.HttpResponse<byte[]> real) {
            StringBuilder raw = new StringBuilder("HTTP/1.1 ").append(real.statusCode()).append(" RES\r\n");
            real.headers().map().forEach((name, values) -> {
                if (!name.startsWith(":")) {
                    for (String v : values) {
                        raw.append(name).append(": ").append(v).append("\r\n");
                    }
                }
            });
            raw.append("\r\n");
            byte[] head = raw.toString().getBytes(StandardCharsets.UTF_8);
            byte[] body = real.body() == null ? new byte[0] : real.body();
            byte[] full = new byte[head.length + body.length];
            System.arraycopy(head, 0, full, 0, head.length);
            System.arraycopy(body, 0, full, head.length, body.length);
            return MontoyaStubs.response(full);
        }
    }

    // -- helpers -------------------------------------------------------------

    private static MontoyaApi stubApi() {
        MontoyaApi api = mock(MontoyaApi.class, RETURNS_DEEP_STUBS);
        lenient().when(api.scope().isInScope(anyString())).thenReturn(true);
        return api;
    }

    private static String hostOf(HttpRequest request) {
        try {
            HttpService service = request.httpService();
            return (service.secure() ? "https" : "http") + "://" + service.host() + ":" + service.port();
        } catch (Exception e) {
            try {
                return URI.create(request.url()).getHost();
            } catch (Exception ignored) {
                return "unknown";
            }
        }
    }

    private static List<String> pickPerHost(List<String> urls, int perHost) {
        Map<String, List<String>> byHost = new LinkedHashMap<>();
        for (String url : urls) {
            String host = hostKey(url);
            byHost.computeIfAbsent(host, h -> new ArrayList<>()).add(url);
        }
        List<String> picked = new ArrayList<>();
        for (List<String> hostUrls : byHost.values()) {
            picked.addAll(hostUrls.subList(0, Math.min(perHost, hostUrls.size())));
        }
        return picked;
    }

    private static long distinctHosts(List<String> urls) {
        return urls.stream().map(SweepHarness::hostKey).distinct().count();
    }

    private static String hostKey(String url) {
        try {
            return URI.create(url.trim()).getHost();
        } catch (Exception e) {
            return "?";
        }
    }

    private static List<String> loadUrls(Path listFile) throws Exception {
        List<String> urls = new ArrayList<>();
        for (String line : Files.readAllLines(listFile)) {
            String t = line.trim();
            if (!t.isEmpty() && !t.startsWith("#") && (t.startsWith("http://") || t.startsWith("https://"))) {
                urls.add(t);
            }
        }
        return urls;
    }

    private static HttpClient buildClient(Config config) throws Exception {
        HttpClient.Builder builder = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .followRedirects(HttpClient.Redirect.NEVER);
        if (config.insecure()) {
            SSLContext ssl = SSLContext.getInstance("TLS");
            ssl.init(null, new TrustManager[]{trustAll()}, new SecureRandom());
            builder.sslContext(ssl);
        }
        return builder.build();
    }

    private static X509TrustManager trustAll() {
        return new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) {}
            public void checkServerTrusted(X509Certificate[] c, String a) {}
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        };
    }

    private static Map<Integer, Integer> toIntMap(Map<Integer, AtomicInteger> in) {
        Map<Integer, Integer> out = new java.util.HashMap<>();
        in.forEach((k, v) -> out.put(k, v.get()));
        return out;
    }

    private static String safe(String v) {
        return v == null ? "-" : v;
    }

    private static String abbreviate(String v, int max) {
        return v.length() <= max ? v : v.substring(0, max - 1) + "…";
    }

    private record Config(Path listFile, int perHostCandidates, int maxHosts, int maxProbes,
                          int globalConcurrency, int perHostConcurrency, int maxSeconds,
                          int pauseAfterConsecutive, int pauseSeconds,
                          CoverageSweepPayloadSet payloadSet, boolean insecure) {}

    private static Config parse(String[] args) {
        Path listFile = Path.of("C:/Users/jonat/Downloads/bf_me.txt");
        int perHostCandidates = 1;
        int maxHosts = Integer.MAX_VALUE;
        int maxProbes = 80;
        int globalConcurrency = 200;
        int perHostConcurrency = 50;
        int maxSeconds = 120;
        int pauseAfterConsecutive = 0;
        int pauseSeconds = 0;
        CoverageSweepPayloadSet payloadSet = CoverageSweepPayloadSet.HIGH_SIGNAL;
        boolean insecure = false;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--per-host-candidates" -> perHostCandidates = Integer.parseInt(args[++i]);
                case "--max-hosts" -> maxHosts = Integer.parseInt(args[++i]);
                case "--max-probes" -> maxProbes = Integer.parseInt(args[++i]);
                case "--global" -> globalConcurrency = Integer.parseInt(args[++i]);
                case "--per-host" -> perHostConcurrency = Integer.parseInt(args[++i]);
                case "--max-seconds" -> maxSeconds = Integer.parseInt(args[++i]);
                case "--pause-after-consecutive" -> pauseAfterConsecutive = Integer.parseInt(args[++i]);
                case "--pause-seconds" -> pauseSeconds = Integer.parseInt(args[++i]);
                case "--payloads" -> payloadSet = args[++i].startsWith("all")
                    ? CoverageSweepPayloadSet.ALL_PAYLOADS : CoverageSweepPayloadSet.HIGH_SIGNAL;
                case "--insecure" -> insecure = true;
                default -> {
                    if (!args[i].startsWith("-")) {
                        listFile = Path.of(args[i]);
                    }
                }
            }
        }
        return new Config(listFile, perHostCandidates, maxHosts, maxProbes, globalConcurrency,
            perHostConcurrency, maxSeconds, pauseAfterConsecutive, pauseSeconds, payloadSet, insecure);
    }

    private static List<String> limitHosts(List<String> urls, int maxHosts) {
        if (maxHosts <= 0 || maxHosts == Integer.MAX_VALUE) return urls;
        Set<String> selected = new java.util.LinkedHashSet<>();
        List<String> result = new ArrayList<>();
        for (String url : urls) {
            String host = hostKey(url);
            if (!selected.contains(host) && selected.size() >= maxHosts) continue;
            selected.add(host);
            result.add(url);
        }
        return result;
    }

    private SweepHarness() {}
}

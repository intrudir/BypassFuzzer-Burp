package com.bypassfuzzer.burp.core.throttle;
import com.bypassfuzzer.core.throttle.ThrottleSettings;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse.BodyHandlers;
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
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Standalone live-fire harness that fuzzes a URL list <em>exactly the way BypassFuzzer's coverage
 * sweep does</em>: it drives the real production {@link HostThrottleCoordinator} — the same per-host
 * admission funnel sweep mode uses — with a browser User-Agent, one adaptive controller per host, and
 * throttled requests re-queued rather than dropped. The only thing swapped for the standalone context
 * is the transport: a {@link java.net.http.HttpClient} in place of Burp's Montoya sender (the request
 * and response are wrapped as Montoya objects via {@link HarnessMontoya} so the coordinator sees the
 * same interface it does in Burp).
 *
 * <p>Not a JUnit test (has a {@code main}, no {@code @Test}), so {@code gradle test} skips it. Run:</p>
 * <pre>
 *   ./gradlew compileTestJava
 *   java -cp build/classes/java/test:build/classes/java/main \
 *        com.bypassfuzzer.burp.core.throttle.LiveThrottleHarness \
 *        C:/Users/jonat/Downloads/bf_me.txt --max-requests 3000 --max-seconds 180 --insecure
 * </pre>
 *
 * <p><b>This sends real HTTP requests to every host in the list.</b> Only run it against targets you
 * are authorised to test. Safety caps (`--max-requests`, `--max-seconds`, `--max-rate`) bound a run.</p>
 */
public final class LiveThrottleHarness {

    private static final String BROWSER_UA =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
            + "Chrome/126.0.0.0 Safari/537.36";

    private record Config(
        Path listFile, String userAgent, int maxRequests, int maxSeconds, double maxRatePerHost,
        int globalConcurrency, int perHostConcurrency, String method, Set<Integer> throttleCodes,
        boolean insecure, boolean loop) {}

    /** Per-host tallies (the coordinator owns the adaptive rate; we only count outcomes). */
    private static final class HostStats {
        final AtomicInteger sent = new AtomicInteger();
        final AtomicInteger throttled = new AtomicInteger();
        final AtomicInteger errors = new AtomicInteger();
        final Map<Integer, AtomicInteger> statusCounts = new ConcurrentHashMap<>();
        volatile long firstSendNanos = -1;
        volatile long lastSendNanos = -1;
    }

    public static void main(String[] args) throws Exception {
        Config config = parse(args);
        if (config == null) {
            return;
        }

        List<String> urls = loadUrls(config.listFile());
        Map<String, HostStats> stats = new ConcurrentHashMap<>();
        Map<String, List<String>> byHost = groupByHost(urls);
        System.out.printf("Loaded %d URLs across %d hosts. UA=%s, method=%s; caps: maxReq=%d maxSec=%d "
                + "maxRate/host=%.0f/s, global=%d, per-host=%d%n",
            urls.size(), byHost.size(), abbreviate(config.userAgent(), 40), config.method(),
            config.maxRequests(), config.maxSeconds(), config.maxRatePerHost(),
            config.globalConcurrency(), config.perHostConcurrency());

        // The real production funnel: one coordinator, per-host adaptive controllers created lazily.
        ThrottleSettings settings = new ThrottleSettings(config.throttleCodes(),
            config.globalConcurrency(), config.perHostConcurrency(), config.maxRatePerHost(),
            ThrottleSettings.Posture.RIDE_HARD);
        HostThrottleCoordinator coordinator = new HostThrottleCoordinator(settings, null);

        HttpClient client = buildClient(config);
        ConcurrentLinkedQueue<String> queue = new ConcurrentLinkedQueue<>(urls);
        ConcurrentLinkedQueue<String> retries = new ConcurrentLinkedQueue<>();
        AtomicInteger globalSent = new AtomicInteger();
        long startNanos = System.nanoTime();
        long deadlineNanos = startNanos + TimeUnit.SECONDS.toNanos(config.maxSeconds());

        int workers = Math.min(config.globalConcurrency(), Math.max(1, urls.size()));
        ExecutorService pool = Executors.newFixedThreadPool(workers);
        CountDownLatch done = new CountDownLatch(workers);
        Thread monitor = startMonitor(coordinator, stats, globalSent, startNanos);

        for (int i = 0; i < workers; i++) {
            pool.submit(() -> {
                try {
                    worker(coordinator, client, config, queue, retries, stats, globalSent, deadlineNanos);
                } finally {
                    done.countDown();
                }
            });
        }
        done.await();
        pool.shutdownNow();
        monitor.interrupt();
        printSummary(coordinator, stats, retries.size(), startNanos, System.nanoTime());
    }

    private static void worker(HostThrottleCoordinator coordinator, HttpClient client, Config config,
                               ConcurrentLinkedQueue<String> queue, ConcurrentLinkedQueue<String> retries,
                               Map<String, HostStats> stats, AtomicInteger globalSent, long deadlineNanos) {
        while (System.nanoTime() < deadlineNanos && globalSent.get() < config.maxRequests()) {
            String url = queue.poll();
            if (url == null) {
                url = retries.poll(); // drain re-queued throttles once the main list is exhausted
            }
            if (url == null) {
                return;
            }
            String finalUrl = url;
            HttpRequest request = HarnessMontoya.request(finalUrl);
            String hostKey = HostThrottleCoordinator.hostKey(request);
            HostStats host = stats.computeIfAbsent(hostKey, k -> new HostStats());

            // Drive the real coordinator: it paces this host and reports the response to the
            // per-host adaptive controller, exactly as in sweep mode.
            HttpResponse response = coordinator.send(request, () -> sendReal(client, config, finalUrl, host));
            if (response == null) {
                continue;
            }
            if (globalSent.incrementAndGet() > config.maxRequests()) {
                return;
            }
            int status = response.statusCode();
            host.statusCounts.computeIfAbsent(status, s -> new AtomicInteger()).incrementAndGet();
            if (coordinator.isThrottleStatusCode(status)) {
                host.throttled.incrementAndGet();
                retries.add(finalUrl); // ride-hard: re-queue blocked requests so coverage stays complete
            } else if (config.loop()) {
                queue.add(finalUrl); // sustain per-host load so the controller can find and ride the ceiling
            }
        }
    }

    private static final Map<String, AtomicInteger> SIGNATURES = new ConcurrentHashMap<>();
    private static final Map<Integer, String> SAMPLE_HEADERS = new ConcurrentHashMap<>();

    private static HttpResponse sendReal(HttpClient client, Config config, String url, HostStats host) {
        long now = System.nanoTime();
        if (host.firstSendNanos < 0) {
            host.firstSendNanos = now;
        }
        host.lastSendNanos = now;
        host.sent.incrementAndGet();
        try {
            java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(15))
                .header("User-Agent", config.userAgent())
                .header("Accept", "*/*")
                .method(config.method(), java.net.http.HttpRequest.BodyPublishers.noBody())
                .build();
            var real = client.send(request, BodyHandlers.ofByteArray());
            var headers = real.headers();
            byte[] body = real.body() == null ? new byte[0] : real.body();
            String bodyPrefix = new String(body, 0, Math.min(body.length, 60),
                java.nio.charset.StandardCharsets.UTF_8).replaceAll("\\s+", " ").trim();
            // Fingerprint the response so a rate-limit variant (different body / server / edge
            // headers) shows up distinctly from a normal blocked-endpoint 403.
            String sig = real.statusCode()
                + " | len=" + body.length
                + " | server=" + headers.firstValue("server").orElse("-")
                + " | via=" + headers.firstValue("via").orElse("-")
                + " | retry-after=" + headers.firstValue("retry-after").orElse("-")
                + " | body=\"" + bodyPrefix + "\"";
            SIGNATURES.computeIfAbsent(sig, s -> new AtomicInteger()).incrementAndGet();
            SAMPLE_HEADERS.computeIfAbsent(real.statusCode(), s -> headers.map().toString());
            String retryAfter = headers.firstValue("retry-after").orElse(null);
            return HarnessMontoya.response(real.statusCode(), retryAfter);
        } catch (Exception e) {
            host.errors.incrementAndGet();
            return null; // transport failure: coordinator treats null as "no report", no penalty
        }
    }


    private static Thread startMonitor(HostThrottleCoordinator coordinator, Map<String, HostStats> stats,
                                       AtomicInteger globalSent, long startNanos) {
        Thread monitor = new Thread(() -> {
            try {
                while (!Thread.currentThread().isInterrupted()) {
                    TimeUnit.SECONDS.sleep(3);
                    double elapsed = (System.nanoTime() - startNanos) / 1e9;
                    int throttled = stats.values().stream().mapToInt(h -> h.throttled.get()).sum();
                    double topRate = stats.keySet().stream()
                        .mapToDouble(coordinator::currentRateForHost).max().orElse(0);
                    System.out.printf("  [%3.0fs] sent=%d throttled=%d (%.1f%%) aggregate=%.0f req/s  top host=%.0f/s%n",
                        elapsed, globalSent.get(), throttled,
                        globalSent.get() == 0 ? 0 : 100.0 * throttled / globalSent.get(),
                        elapsed > 0 ? globalSent.get() / elapsed : 0, topRate);
                }
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }, "live-throttle-monitor");
        monitor.setDaemon(true);
        monitor.start();
        return monitor;
    }

    private static void printSummary(HostThrottleCoordinator coordinator, Map<String, HostStats> stats,
                                     int retriesRemaining, long startNanos, long endNanos) {
        System.out.printf("%n%-46s %7s %6s %8s %8s %9s %8s%n",
            "host", "sent", "429", "throttle", "rate/s", "delay/req", "goodput");
        int totalSent = 0;
        int totalThrottled = 0;
        List<Map.Entry<String, HostStats>> rows = new ArrayList<>(stats.entrySet());
        rows.sort(Map.Entry.comparingByKey());
        for (Map.Entry<String, HostStats> entry : rows) {
            HostStats host = entry.getValue();
            int sent = host.sent.get();
            int throttled = host.throttled.get();
            totalSent += sent;
            totalThrottled += throttled;
            double span = host.firstSendNanos > 0 && host.lastSendNanos > host.firstSendNanos
                ? (host.lastSendNanos - host.firstSendNanos) / 1e9 : 0;
            double goodput = span > 0 ? (sent - throttled) / span : 0;
            double rate = coordinator.currentRateForHost(entry.getKey());
            double delayMs = rate > 0 ? 1000.0 / rate : 0;
            System.out.printf("%-46s %7d %6d %7.1f%% %8.1f %7.1fms %8.1f%n",
                abbreviate(entry.getKey(), 46), sent, throttled,
                sent == 0 ? 0 : 100.0 * throttled / sent,
                rate, delayMs, goodput);
        }
        double totalSpan = (endNanos - startNanos) / 1e9;
        System.out.printf("%n%-52s %7d %7d %7.1f%%   time %.1fs, aggregate %.0f req/s, %d retries left%n",
            "TOTAL", totalSent, totalThrottled,
            totalSent == 0 ? 0 : 100.0 * totalThrottled / totalSent,
            totalSpan, totalSpan > 0 ? totalSent / totalSpan : 0, retriesRemaining);

        // Raw response-code distribution -- so a non-{429,503} rate-limit signal (e.g. Yahoo's 999)
        // is visible even though the controller did not treat it as a throttle.
        Map<Integer, Integer> codes = new java.util.TreeMap<>();
        for (HostStats host : stats.values()) {
            host.statusCounts.forEach((code, count) -> codes.merge(code, count.get(), Integer::sum));
        }
        System.out.println("\nResponse codes seen (status -> count): " + codes);

        System.out.println("\nDistinct response fingerprints (most common first):");
        SIGNATURES.entrySet().stream()
            .sorted((a, b) -> Integer.compare(b.getValue().get(), a.getValue().get()))
            .limit(20)
            .forEach(e -> System.out.printf("  %6d  %s%n", e.getValue().get(), e.getKey()));

        SAMPLE_HEADERS.forEach((code, hdrs) ->
            System.out.println("\nSample headers for HTTP " + code + ":\n  " + hdrs));
    }

    private static Map<String, List<String>> groupByHost(List<String> urls) {
        Map<String, List<String>> byHost = new LinkedHashMap<>();
        for (String url : urls) {
            String key = HostThrottleCoordinator.hostKey(HarnessMontoya.request(url));
            byHost.computeIfAbsent(key, k -> new ArrayList<>()).add(url);
        }
        return byHost;
    }

    private static List<String> loadUrls(Path listFile) throws Exception {
        List<String> urls = new ArrayList<>();
        for (String line : Files.readAllLines(listFile)) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty() && !trimmed.startsWith("#")
                && (trimmed.startsWith("http://") || trimmed.startsWith("https://"))) {
                urls.add(trimmed);
            }
        }
        return urls;
    }

    private static HttpClient buildClient(Config config) throws Exception {
        HttpClient.Builder builder = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .followRedirects(HttpClient.Redirect.NEVER);
        if (config.insecure()) {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{trustAll()}, new SecureRandom());
            builder.sslContext(sslContext);
        }
        return builder.build();
    }

    private static X509TrustManager trustAll() {
        return new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) {}
            public void checkServerTrusted(X509Certificate[] chain, String authType) {}
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        };
    }

    private static Config parse(String[] args) {
        Path listFile = Path.of("C:/Users/jonat/Downloads/bf_me.txt");
        String ua = BROWSER_UA;
        int maxRequests = 3000;
        int maxSeconds = 180;
        double maxRatePerHost = 200;
        int globalConcurrency = 200;
        int perHostConcurrency = 50;
        String method = "GET";
        Set<Integer> throttleCodes = Set.of(429, 503);
        boolean insecure = false;
        boolean loop = false;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-h", "--help" -> {
                    System.out.println("Usage: LiveThrottleHarness [list-file] [--ua <s>] [--max-requests N] "
                        + "[--max-seconds N] [--max-rate R] [--global N] [--per-host N] [--method GET|HEAD] "
                        + "[--throttle-codes 429,503] [--insecure] [--loop]");
                    return null;
                }
                case "--ua" -> ua = args[++i];
                case "--max-requests" -> maxRequests = Integer.parseInt(args[++i]);
                case "--max-seconds" -> maxSeconds = Integer.parseInt(args[++i]);
                case "--max-rate" -> maxRatePerHost = Double.parseDouble(args[++i]);
                case "--global" -> globalConcurrency = Integer.parseInt(args[++i]);
                case "--per-host" -> perHostConcurrency = Integer.parseInt(args[++i]);
                case "--method" -> method = args[++i].toUpperCase();
                case "--throttle-codes" -> throttleCodes = parseCodes(args[++i]);
                case "--insecure" -> insecure = true;
                case "--loop" -> loop = true;
                default -> {
                    if (!args[i].startsWith("-")) {
                        listFile = Path.of(args[i]);
                    }
                }
            }
        }
        return new Config(listFile, ua, maxRequests, maxSeconds, maxRatePerHost, globalConcurrency,
            perHostConcurrency, method, throttleCodes, insecure, loop);
    }

    private static Set<Integer> parseCodes(String csv) {
        Set<Integer> codes = new java.util.HashSet<>();
        for (String part : csv.split(",")) {
            if (!part.isBlank()) {
                codes.add(Integer.parseInt(part.trim()));
            }
        }
        return codes;
    }

    private static String abbreviate(String value, int max) {
        return value.length() <= max ? value : value.substring(0, max - 1) + "…";
    }

    private LiveThrottleHarness() {}
}

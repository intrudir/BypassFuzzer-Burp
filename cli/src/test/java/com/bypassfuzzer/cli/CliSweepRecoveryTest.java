package com.bypassfuzzer.cli;

import com.bypassfuzzer.cli.evidence.EvidenceWriter;
import com.bypassfuzzer.cli.run.*;
import com.bypassfuzzer.core.http.*;
import com.bypassfuzzer.core.scan.*;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

class CliSweepRecoveryTest {
    @TempDir Path temporary;
    @Test void recoveredSweepMutationIsFlaggedAndCountedForBothWorkflowModes() throws Exception {
        for (boolean authenticated : List.of(false, true)) {
            Path out = temporary.resolve(authenticated ? "authenticated" : "blocked");
            var seed = new RawHttpRequestParser().parse(("GET /blocked HTTP/1.1\r\nHost: example.test\r\n"
                + (authenticated ? "Authorization: fixture\r\n" : "") + "\r\n").getBytes(), TargetOrigin.parse("http://example.test"));
            var options = new ExecutionOptions(out, HttpProtocol.HTTP_1, Duration.ofSeconds(2), 1, 1,
                Set.of(429), false, 1, "ride-hard", "off", 1000, false);
            var policy = new RequestHeaderPolicy<>(RequestAccess.CORE, List.of(), UserAgentMode.DISABLED, 0);
            var mutations = new AtomicInteger();
            try (var evidence = new EvidenceWriter(out, "recovery", false, Map.of()); var control = new RunControl(null, null, null)) {
                new SweepExecutor().run(List.of(seed), base -> {
                    var plan = new ArrayList<PlannedRequest>();
                    if (!authenticated) plan.add(PlannedRequest.baseline(base, "Original request"));
                    plan.add(new PlannedRequest("Path", "mutation", "", base.withRawTarget("/mutation"), false));
                    return plan;
                }, (request, timeout) -> new HttpResponseData(HttpProtocol.HTTP_1,
                    request.firstHeader("Authorization").isPresent() ? 200 : request.rawTarget().equals("/mutation")
                        ? mutations.incrementAndGet() == 1 ? 429 : 200 : 403,
                    List.of(new HttpHeader("Content-Type", "text/plain")), new byte[0], 1), options,
                    new SweepWorkflow.Options(authenticated, authenticated, true, Set.of("Authorization"), Set.of(), false, Set.of(429)), policy, evidence, control);
            }
            var rows = Files.readAllLines(out.resolve("results.jsonl")).stream().map(line -> JsonParser.parseString(line).getAsJsonObject()).toList();
            var recovered = rows.stream().filter(row -> row.get("retryAttempt").getAsInt() == 1).findFirst().orElseThrow();
            assertEquals(200, recovered.get("status").getAsInt());
            assertEquals(authenticated ? "BYPASS?: authenticated 200 -> anonymous 403 -> probe 200" : "403 -> 200", recovered.get("signal").getAsString());
            var summary = JsonParser.parseString(Files.readString(out.resolve("summary.json"))).getAsJsonObject();
            assertEquals(1, summary.get("findings").getAsInt());
            assertEquals(0, summary.get("deferredRetries").getAsInt());
            assertEquals(2, mutations.get());
        }
    }
}

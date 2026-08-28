package com.bypassfuzzer.burp.core.idor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.idor.playbooks.IdorPlaybook;
import com.bypassfuzzer.burp.core.idor.playbooks.IdorPlaybookRegistry;
import com.bypassfuzzer.burp.core.idor.playbooks.IdorRequestVariant;
import com.bypassfuzzer.burp.http.LocatedParameter;
import com.bypassfuzzer.burp.http.ParameterLocation;
import com.bypassfuzzer.burp.http.RequestSender;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;

class IdorEngineTest {

    @Test
    void engineLabelsAndRunsRegisteredPlaybooksAfterBaselines() throws InterruptedException {
        HttpRequest originalRequest = request("https://example.com/users/1", "/users/1");
        HttpRequest targetRequest = request("https://example.com/users/2", "/users/2");
        HttpRequest playbookRequest = request("https://example.com/users/2.json", "/users/2.json");
        CountDownLatch completion = new CountDownLatch(1);
        List<AttackResult> results = new ArrayList<>();
        AtomicReference<HttpRequest> variantRequest = new AtomicReference<>();

        IdorRequestContextAnalyzer contextAnalyzer = new IdorRequestContextAnalyzer(new IdorRequestMutator() {
            @Override
            public HttpRequest replaceIdentifier(HttpRequest request, String sourceIdentifier, String targetIdentifier) {
                return targetRequest;
            }
        }) {
            @Override
            public IdorRequestContext analyze(HttpRequest request, IdorOptions options) {
                return new IdorRequestContext(
                    originalRequest,
                    targetRequest,
                    options,
                    List.of(new LocatedParameter("id", "2", ParameterLocation.QUERY))
                );
            }
        };

        IdorPlaybookRegistry playbookRegistry = new IdorPlaybookRegistry() {
            @Override
            public List<IdorPlaybook> all() {
                return List.of(new IdorPlaybook() {
                    @Override
                    public String id() {
                        return "idor.test.synthetic";
                    }

                    @Override
                    public String displayName() {
                        return "Synthetic";
                    }

                    @Override
                    public String description() {
                        return "Test playbook";
                    }

                    @Override
                    public List<IdorRequestVariant> buildVariants(IdorRequestContext context) {
                        variantRequest.set(playbookRequest);
                        return List.of(new IdorRequestVariant("synthetic variant", playbookRequest));
                    }
                });
            }
        };

        IdorEngine engine = new IdorEngine(
            mock(MontoyaApi.class, RETURNS_DEEP_STUBS),
            contextAnalyzer,
            playbookRegistry,
            new NullResponseRequestSender()
        );

        boolean started = engine.start(
            originalRequest,
            new IdorOptions("1", "2", runOptions()),
            results::add,
            completion::countDown
        );

        assertTrue(started);
        assertTrue(completion.await(5, TimeUnit.SECONDS));
        assertEquals(3, results.size());
        assertEquals("Control: authorized identifier 1 (1)", results.get(0).getPayload());
        assertEquals("Control", results.get(0).getTargetLabel());
        assertEquals("idor.baseline.control", results.get(0).getPayloadFamily());
        assertEquals("Baseline: identifier 2 without bypass (2)", results.get(1).getPayload());
        assertEquals("Baseline", results.get(1).getTargetLabel());
        assertEquals("idor.baseline.target", results.get(1).getPayloadFamily());
        assertEquals("synthetic variant", results.get(2).getPayload());
        assertEquals("Synthetic", results.get(2).getTargetLabel());
        assertEquals("idor.test.synthetic", results.get(2).getPayloadFamily());
        assertSame(targetRequest, results.get(1).getRequest());
        assertSame(playbookRequest, variantRequest.get());
        assertSame(playbookRequest, results.get(2).getRequest());
        assertEquals(3, engine.httpRequestsSent());
    }

    private static IdorRunOptions runOptions() {
        return new IdorRunOptions(Set.of());
    }

    private static HttpRequest request(String url, String path) {
        HttpService service = (HttpService) Proxy.newProxyInstance(
            HttpService.class.getClassLoader(),
            new Class<?>[]{HttpService.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "host" -> "example.com";
                case "port" -> 443;
                case "secure" -> true;
                case "ipAddress" -> "example.com";
                case "toString" -> "https://example.com";
                default -> defaultValue(method.getReturnType());
            }
        );

        return (HttpRequest) Proxy.newProxyInstance(
            HttpRequest.class.getClassLoader(),
            new Class<?>[]{HttpRequest.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "httpService" -> service;
                case "url" -> url;
                case "path" -> path;
                case "query" -> null;
                case "pathWithoutQuery" -> path;
                case "toString" -> "GET " + path + " HTTP/1.1\r\nHost: example.com\r\n\r\n";
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == args[0];
                default -> defaultValue(method.getReturnType());
            }
        );
    }

    private static Object defaultValue(Class<?> returnType) {
        if (returnType == boolean.class) {
            return false;
        }
        if (returnType == int.class) {
            return 0;
        }
        if (returnType == long.class) {
            return 0L;
        }
        if (returnType == short.class) {
            return (short) 0;
        }
        return null;
    }

    private static final class NullResponseRequestSender implements RequestSender {
        @Override
        public HttpResponse send(HttpRequest request) {
            return null;
        }

        @Override
        public HttpResponse send(HttpRequest request, long timeout, TimeUnit timeUnit) {
            return null;
        }
    }
}

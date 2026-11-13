package com.bypassfuzzer.cli.transport;

import com.bypassfuzzer.core.http.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.KeyStore;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;

import static org.junit.jupiter.api.Assertions.*;

class NettyRequestTransportSafetyTest {
    @TempDir Path temporary;

    @Test void tlsChecksTrustedPeerIdentityAndKeepsExplicitInsecureMode() throws Exception {
        Path store = temporary.resolve("fixture.p12");
        var generate = new ProcessBuilder(tool("keytool"), "-genkeypair", "-alias", "fixture", "-keyalg", "RSA",
            "-keysize", "2048", "-dname", "CN=localhost", "-ext", "SAN=dns:localhost", "-validity", "2",
            "-storetype", "PKCS12", "-keystore", store.toString(), "-storepass", "fixture-pass",
            "-keypass", "fixture-pass", "-noprompt").redirectErrorStream(true).start();
        assertTrue(generate.waitFor(20, TimeUnit.SECONDS));
        assertEquals(0, generate.exitValue(), new String(generate.getInputStream().readAllBytes()));
        var keys = KeyStore.getInstance("PKCS12");
        try (var input = Files.newInputStream(store)) { keys.load(input, "fixture-pass".toCharArray()); }
        var managers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        managers.init(keys, "fixture-pass".toCharArray());
        var context = SSLContext.getInstance("TLS"); context.init(managers.getKeyManagers(), null, null);
        try (var server = (SSLServerSocket) context.getServerSocketFactory().createServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            var worker = Executors.newSingleThreadExecutor();
            var serving = worker.submit(() -> {
                while (!server.isClosed()) {
                    try (var socket = (SSLSocket) server.accept()) {
                        socket.setSoTimeout(5000); socket.startHandshake();
                        var input = new BufferedReader(new InputStreamReader(socket.getInputStream(), java.nio.charset.StandardCharsets.ISO_8859_1));
                        String first = input.readLine();
                        if (first == null) continue;
                        if (first.split(" ").length >= 3) while (true) {
                            String line = input.readLine(); if (line == null || line.isEmpty()) break;
                        }
                        socket.getOutputStream().write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".getBytes());
                    } catch (IOException expectedHandshakeOrShutdown) { }
                }
            });
            try {
                int port = server.getLocalPort();
                assertTrue(tlsProbe(store, "localhost", port, "http1", false, true).contains("STATUS=200"));
                assertTrue(tlsProbe(store, "127.0.0.1", port, "http1", false, false).contains("SSLHandshakeException"));
                assertTrue(tlsProbe(null, "localhost", port, "http1", false, false).contains("SSLHandshakeException"));
                assertTrue(tlsProbe(store, "127.0.0.1", port, "http1", true, true).contains("STATUS=200"));
                assertTrue(tlsProbe(store, "localhost", port, "http0.9", false, true).contains("STATUS=200"));
                assertTrue(tlsProbe(store, "127.0.0.1", port, "http0.9", false, false).contains("SSLHandshakeException"));
            } finally { server.close(); worker.shutdownNow(); assertTrue(worker.awaitTermination(10, TimeUnit.SECONDS)); }
        }
    }

    @Test void headerlessEmptyDisconnectIsUnavailableButRealBodyIsRetained() throws Exception {
        try (var server = new RawServer(new byte[0], 0); var transport = new NettyRequestTransport(false, null)) {
            Exception error = assertThrows(Exception.class, () -> transport.send(server.request(), Duration.ofSeconds(5)));
            assertTrue(root(error) instanceof EOFException, error.toString());
        }
        try (var server = new RawServer("body-only".getBytes(), 1); var transport = new NettyRequestTransport(false, null)) {
            var response = transport.send(server.request(), Duration.ofSeconds(5));
            assertEquals(HttpProtocol.HTTP_0_9, response.protocol());
            assertArrayEquals("body-only".getBytes(), response.body());
        }
    }

    @Test void headerlessResponseLimitAccepts64MiBAndRejects65MiB() throws Exception {
        byte[] chunk = new byte[1024 * 1024];
        try (var server = new RawServer(chunk, 64); var transport = new NettyRequestTransport(false, null)) {
            assertEquals(64 * 1024 * 1024, transport.send(server.request(), Duration.ofSeconds(15)).bodyLength());
        }
        try (var server = new RawServer(chunk, 65); var transport = new NettyRequestTransport(false, null)) {
            Exception error = assertThrows(Exception.class, () -> transport.send(server.request(), Duration.ofSeconds(15)));
            assertTrue(root(error).getMessage().contains("Response exceeded 67108864 bytes"), error.toString());
        }
    }

    private String tlsProbe(Path store, String host, int port, String protocol, boolean insecure, boolean success) throws Exception {
        var args = new ArrayList<String>(List.of(tool("java"), "-Djava.net.preferIPv4Stack=true"));
        if (store != null) args.addAll(List.of("-Djavax.net.ssl.trustStore=" + store,
            "-Djavax.net.ssl.trustStorePassword=fixture-pass"));
        args.addAll(List.of("-cp", classpath(), NettyTlsProbe.class.getName(), "https://" + host + ":" + port, protocol, String.valueOf(insecure)));
        Process process = new ProcessBuilder(args).redirectErrorStream(true).start();
        try {
            assertTrue(process.waitFor(20, TimeUnit.SECONDS));
            String output = new String(process.getInputStream().readAllBytes());
            assertEquals(success, process.exitValue() == 0, output);
            return output;
        } finally { process.destroyForcibly(); }
    }

    private static String tool(String name) {
        return Path.of(System.getProperty("java.home"), "bin", name + (System.getProperty("os.name").startsWith("Windows") ? ".exe" : "")).toString();
    }
    private static String classpath() throws Exception {
        String paths = System.getProperty("bypassfuzzer.test.classpath");
        assertNotNull(paths, "Child TLS probe requires the Gradle test runtime classpath");
        return paths;
    }

    private static Throwable root(Throwable error) { while (error.getCause() != null) error = error.getCause(); return error; }

    private static final class RawServer implements AutoCloseable {
        final ServerSocket server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        final ExecutorService worker = Executors.newSingleThreadExecutor();
        RawServer(byte[] chunk, int copies) throws IOException {
            worker.submit(() -> {
                try (var socket = server.accept()) {
                    socket.setSoTimeout(5000);
                    var input = socket.getInputStream(); int value; while ((value = input.read()) != -1 && value != '\n') { }
                    for (int n = 0; n < copies; n++) socket.getOutputStream().write(chunk);
                } catch (IOException rejectedOrClosed) { }
            });
        }
        HttpRequestData request() {
            var origin = new TargetOrigin("http", "127.0.0.1", server.getLocalPort());
            return new HttpRequestData(origin, "GET", "/response", HttpProtocol.HTTP_0_9, List.of(), new byte[0]);
        }
        @Override public void close() throws Exception { server.close(); worker.shutdownNow(); assertTrue(worker.awaitTermination(10, TimeUnit.SECONDS)); }
    }
}

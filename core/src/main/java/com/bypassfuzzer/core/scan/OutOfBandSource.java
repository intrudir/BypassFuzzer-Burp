package com.bypassfuzzer.core.scan;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/** Host integration for native Collaborator or another operator-controlled payload generator. */
public final class OutOfBandSource {
    private OutOfBandSource() { }
    public static Supplier<String> configured(String domain, Path generator) {
        if (domain != null && generator != null)
            throw new IllegalArgumentException("Choose --oob-domain or --oob-generator, not both");
        if (generator == null) {
            String normalized = normalize(domain);
            return () -> normalized;
        }
        if (!java.nio.file.Files.isRegularFile(generator) || !java.nio.file.Files.isExecutable(generator))
            throw new IllegalArgumentException("OOB generator must be executable: " + generator);
        return () -> {
            Path stdout = null;
            try {
                stdout = java.nio.file.Files.createTempFile("bypassfuzzer-oob-", ".txt");
                Process process = new ProcessBuilder(generator.toAbsolutePath().toString())
                    .redirectOutput(stdout.toFile()).redirectError(ProcessBuilder.Redirect.DISCARD).start();
                if (!process.waitFor(15, TimeUnit.SECONDS)) {
                    process.destroyForcibly();
                    throw new IllegalArgumentException("OOB generator timed out");
                }
                if (process.exitValue() != 0) throw new IllegalArgumentException("OOB generator failed");
                String value = normalize(java.nio.file.Files.readString(stdout, StandardCharsets.UTF_8).trim());
                if (value.isEmpty()) throw new IllegalArgumentException("OOB generator returned no hostname");
                return value;
            } catch (java.io.IOException error) {
                throw new IllegalArgumentException("Unable to run OOB generator", error);
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                throw new IllegalArgumentException("OOB generator interrupted", error);
            } finally {
                if (stdout != null) try { java.nio.file.Files.deleteIfExists(stdout); } catch (java.io.IOException ignored) { }
            }
        };
    }
    public static String normalize(String value) {
        if (value == null || value.isBlank()) return "";
        String host = value.trim().replaceFirst("^https?://", "").replaceFirst("/.*$", "");
        if (!host.matches("[A-Za-z0-9.-]+(?::[0-9]+)?"))
            throw new IllegalArgumentException("OOB payload must be a hostname, optionally with a port");
        return host;
    }
}

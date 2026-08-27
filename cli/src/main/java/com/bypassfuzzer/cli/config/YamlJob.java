package com.bypassfuzzer.cli.config;

import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class YamlJob {
    private static final Map<String, Set<String>> KEYS = Map.of(
        "", Set.of("schemaVersion", "input", "transport", "execution", "evidence", "sweep", "bypass", "idor", "urlValidation"),
        "input", Set.of("urls", "request", "targetOrigin", "requestManifest", "openapi", "postman", "retryPackage", "baseUrl"),
        "transport", Set.of("protocol", "proxy", "insecure", "connectTimeoutSeconds", "requestTimeoutSeconds"),
        "execution", Set.of("globalConcurrency", "perHostConcurrency", "throttleStatusCodes", "retryAttempts", "maxProbes", "includeStateChanging", "headers", "userAgentMode", "userAgentSeed", "posture", "pauseMode", "fixedPauseMillis"),
        "evidence", Set.of("output", "redact"),
        "sweep", Set.of("payloadSet", "families"),
        "bypass", Set.of("families", "fuzzExistingCookies"),
        "idor", Set.of("authorizedId", "targetId"),
        "urlValidation", Set.of("marker", "allowedHost", "attackerHost", "scheme", "contexts", "attacks", "encodings")
    );
    private final Path file;
    private final Map<String, Object> root;

    private YamlJob(Path file, Map<String, Object> root) {
        this.file = file.toAbsolutePath().normalize();
        this.root = root;
    }

    @SuppressWarnings("unchecked")
    public static YamlJob load(Path file) throws IOException {
        if (file == null) return new YamlJob(Path.of(".").toAbsolutePath().resolve("job.yaml"), Map.of());
        LoaderOptions options = new LoaderOptions();
        options.setAllowDuplicateKeys(false);
        options.setMaxAliasesForCollections(50);
        Object loaded = new Yaml(new SafeConstructor(options)).load(Files.readString(file, StandardCharsets.UTF_8));
        if (!(loaded instanceof Map<?, ?> map)) throw new IllegalArgumentException("YAML job must be an object");
        Map<String, Object> root = stringMap(map);
        validate("", root);
        Object version = root.get("schemaVersion");
        if (version == null || Integer.parseInt(version.toString()) != 1) throw new IllegalArgumentException("YAML schemaVersion must be 1");
        return new YamlJob(file, root);
    }

    public String string(String section, String key) { Object value = section(section).get(key); return value == null ? null : value.toString(); }
    public Integer integer(String section, String key) { String value = string(section, key); return value == null ? null : Integer.valueOf(value); }
    public Long longValue(String section, String key) { String value = string(section, key); return value == null ? null : Long.valueOf(value); }
    public Boolean bool(String section, String key) { String value = string(section, key); return value == null ? null : Boolean.valueOf(value); }
    public Path path(String section, String key) { String value = string(section, key); if (value == null) return null; Path path = Path.of(value); return path.isAbsolute() ? path : file.getParent().resolve(path).normalize(); }
    public List<String> strings(String section, String key) { Object value = section(section).get(key); if (value == null) return null; if (value instanceof List<?> list) return list.stream().map(Object::toString).toList(); return List.of(value.toString().split(",")); }
    public Map<String, Object> effective() { return root; }

    @SuppressWarnings("unchecked")
    private Map<String, Object> section(String name) { Object value = root.get(name); return value instanceof Map<?, ?> map ? stringMap(map) : Map.of(); }

    private static void validate(String section, Map<String, Object> values) {
        Set<String> allowed = KEYS.get(section);
        for (Map.Entry<String, Object> entry : values.entrySet()) {
            if (entry.getKey().toLowerCase().contains("collaborator")) throw new IllegalArgumentException("Collaborator is not supported by the CLI");
            if (allowed == null || !allowed.contains(entry.getKey())) throw new IllegalArgumentException("Unknown YAML key: " + (section.isEmpty() ? "" : section + ".") + entry.getKey());
            if (KEYS.containsKey(entry.getKey()) && entry.getValue() instanceof Map<?, ?> map) validate(entry.getKey(), stringMap(map));
        }
    }

    private static Map<String, Object> stringMap(Map<?, ?> input) {
        Map<String, Object> result = new LinkedHashMap<>();
        input.forEach((key, value) -> result.put(String.valueOf(key), value));
        return result;
    }
}

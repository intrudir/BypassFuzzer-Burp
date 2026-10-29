package com.bypassfuzzer.core.input;

import java.util.Map;
import java.util.Set;

/** Immutable settings shared by import preview and Sweep request preparation. */
public record OpenApiImportOptions(ParameterPolicy parameterPolicy, Map<String, String> variables) {
    public static final OpenApiImportOptions DEFAULT =
        new OpenApiImportOptions(ParameterPolicy.SAMPLE_VALUES, Map.of());

    public OpenApiImportOptions {
        parameterPolicy = parameterPolicy == null ? ParameterPolicy.SAMPLE_VALUES : parameterPolicy;
        variables = variables == null ? Map.of() : Map.copyOf(variables);
    }

    public enum ParameterPolicy {
        SAMPLE_VALUES("Examples/defaults and generated samples"),
        SOURCE_VALUES_ONLY("Only parameters with source values"),
        REQUIRED_EMPTY("Include missing required parameters as empty"),
        REQUIRED_VARIABLES("Include missing required parameters as {{variables}}"),
        ALL_EMPTY("Include all declared parameters as empty"),
        ALL_VARIABLES("Use {{variables}} for all declared parameters");

        private final String label;

        ParameterPolicy(String label) { this.label = label; }

        @Override public String toString() { return label; }
    }

    public static final class MissingVariablesException extends IllegalArgumentException {
        public MissingVariablesException(Set<String> names) {
            super("Set OpenAPI variables before running: " + String.join(", ", new java.util.TreeSet<>(names)));
        }
    }
}

package com.bypassfuzzer.burp.core.payloads;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Loads payload files from embedded resources or custom file paths.
 * Supports fallback to embedded resources if custom paths are not provided.
 */
public class PayloadLoader {

    private static final String RESOURCE_PATH_PREFIX = "/payloads/";
    private static final String HEADER_TEMPLATES_FILE = "header_payload_templates.txt";
    private static final String IP_PAYLOADS_FILE = "ip_payloads.txt";
    private static final String URL_PAYLOADS_FILE = "url_payloads.txt";

    /**
     * Load header payload templates.
     *
     * @param customPath Optional custom file path, or null to use embedded resource
     * @return List of header payload template strings
     */
    public static List<String> loadHeaderTemplates(String customPath) {
        if (customPath != null && !customPath.isEmpty()) {
            return loadFromFile(customPath);
        }
        return loadFromResource(RESOURCE_PATH_PREFIX + HEADER_TEMPLATES_FILE);
    }

    /**
     * Load IP payloads.
     *
     * @param customPath Optional custom file path, or null to use embedded resource
     * @return List of IP payload strings
     */
    public static List<String> loadIpPayloads(String customPath) {
        if (customPath != null && !customPath.isEmpty()) {
            return loadFromFile(customPath);
        }
        return loadFromResource(RESOURCE_PATH_PREFIX + IP_PAYLOADS_FILE);
    }

    /**
     * Load URL payloads.
     *
     * @param customPath Optional custom file path, or null to use embedded resource
     * @return List of URL payload strings
     */
    public static List<String> loadUrlPayloads(String customPath) {
        if (customPath != null && !customPath.isEmpty()) {
            return loadFromFile(customPath);
        }
        return loadFromResource(RESOURCE_PATH_PREFIX + URL_PAYLOADS_FILE);
    }

    /**
     * Load payloads from embedded resource by filename.
     *
     * @param filename Filename of the payload file
     * @return List of payload strings
     */
    public static List<String> loadPayloads(String filename) {
        return loadFromResource(RESOURCE_PATH_PREFIX + filename);
    }

    /**
     * Load payloads from an embedded resource.
     *
     * @param resourcePath Path to resource (e.g., "/payloads/header_payload_templates.txt")
     * @return List of payload strings, one per line
     */
    private static List<String> loadFromResource(String resourcePath) {
        try (InputStream is = PayloadLoader.class.getResourceAsStream(resourcePath)) {
            if (is == null) {
                throw new RuntimeException("Resource not found: " + resourcePath);
            }

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(is, StandardCharsets.UTF_8))) {
                return reader.lines()
                        .filter(line -> !line.trim().isEmpty())
                        .filter(line -> !line.trim().startsWith("#"))  // Skip comments
                        .collect(Collectors.toList());
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to load resource: " + resourcePath, e);
        }
    }

    /**
     * Load payloads from a custom file path.
     *
     * @param filePath Absolute path to payload file
     * @return List of payload strings, one per line
     */
    private static List<String> loadFromFile(String filePath) {
        try (BufferedReader reader = new BufferedReader(
                new FileReader(filePath, StandardCharsets.UTF_8))) {
            return reader.lines()
                    .filter(line -> !line.trim().isEmpty())
                    .filter(line -> !line.trim().startsWith("#"))  // Skip comments
                    .collect(Collectors.toList());
        } catch (Exception e) {
            throw new RuntimeException("Failed to load file: " + filePath, e);
        }
    }

    /**
     * Validate that a payload file is readable and contains data.
     *
     * @param filePath Path to validate
     * @return true if valid, false otherwise
     */
    public static boolean validatePayloadFile(String filePath) {
        try {
            List<String> payloads = loadFromFile(filePath);
            return !payloads.isEmpty();
        } catch (Exception e) {
            return false;
        }
    }
}

package com.bypassfuzzer.core.payloads;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Central payload repository for embedded fuzzing resources.
 */
public class PayloadRepository {

    private final Random random = new Random();

    public List<String> loadParamPayloads() {
        List<String> payloads;
        try {
            payloads = PayloadLoader.loadPayloads("param_payloads.txt");
        } catch (RuntimeException e) {
            payloads = List.of("debug=true", "debug=1", "admin=true", "admin=1");
        }

        List<String> expanded = new ArrayList<>(payloads);
        for (String payload : payloads) {
            expanded.add(capitalizeParamName(payload));
            expanded.add(upperCaseParamName(payload));
            for (int i = 0; i < 3; i++) {
                expanded.add(randomizeCase(payload));
            }
        }

        return expanded;
    }

    private String capitalizeParamName(String payload) {
        int eqIdx = payload.indexOf('=');
        if (eqIdx <= 0) {
            return payload;
        }

        String name = payload.substring(0, eqIdx);
        String value = payload.substring(eqIdx);
        if (name.isEmpty()) {
            return payload;
        }

        return Character.toUpperCase(name.charAt(0)) + name.substring(1).toLowerCase() + value;
    }

    private String upperCaseParamName(String payload) {
        int eqIdx = payload.indexOf('=');
        if (eqIdx <= 0) {
            return payload;
        }

        String name = payload.substring(0, eqIdx);
        String value = payload.substring(eqIdx);
        return name.toUpperCase() + value;
    }

    private String randomizeCase(String input) {
        StringBuilder result = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (Character.isLetter(c)) {
                result.append(random.nextBoolean() ? Character.toUpperCase(c) : Character.toLowerCase(c));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }
}

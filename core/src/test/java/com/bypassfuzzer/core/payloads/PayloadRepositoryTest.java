package com.bypassfuzzer.core.payloads;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PayloadRepositoryTest {

    @Test
    void expandsEmbeddedParamPayloadsWithCaseVariations() {
        List<String> basePayloads = PayloadLoader.loadPayloads("param_payloads.txt");
        PayloadRepository repository = new PayloadRepository();
        List<String> expandedPayloads = repository.loadParamPayloads();

        assertFalse(basePayloads.isEmpty());
        assertTrue(expandedPayloads.size() > basePayloads.size());
        assertTrue(expandedPayloads.contains(basePayloads.get(0)));
        assertTrue(expandedPayloads.stream().anyMatch(payload -> !basePayloads.contains(payload)));
    }
}

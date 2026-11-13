package com.bypassfuzzer.burp.ui;

import com.bypassfuzzer.burp.core.attacks.AttackResult;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class FuzzerResultsTableModelTest {

    @Test
    void empty404WithoutContentTypeRemainsAResponseInEveryResultsLayout() {
        var response = org.mockito.Mockito.mock(burp.api.montoya.http.message.responses.HttpResponse.class);
        var body = org.mockito.Mockito.mock(burp.api.montoya.core.ByteArray.class);
        org.mockito.Mockito.when(response.statusCode()).thenReturn((short) 404);
        org.mockito.Mockito.when(response.body()).thenReturn(body);
        org.mockito.Mockito.when(response.headers()).thenReturn(java.util.List.of());
        var result = new AttackResult("Calibration", "empty 404", null, response);
        for (var layout : FuzzerResultsTableModel.TableLayout.values()) {
            FuzzerResultsTableModel model = new FuzzerResultsTableModel(layout);
            model.addResult(result, true);
            int status = -1;
            for (int column = 0; column < model.getColumnCount(); column++)
                if (model.getColumnName(column).equals("Status")) status = column;
            org.junit.jupiter.api.Assertions.assertTrue(status >= 0);
            assertEquals(404, model.getValueAt(0, status));
        }
    }

    @Test
    void assignsImmutableRequestIds() {
        FuzzerResultsTableModel model = new FuzzerResultsTableModel();
        AttackResult first = new AttackResult("Header", "one", null, null);
        AttackResult second = new AttackResult("Header", "two", null, null);
        AttackResult third = new AttackResult("Header", "three", null, null);

        model.addResult(first, true);
        model.addResult(second, false);
        model.addResult(third, true);

        assertEquals(1, model.getValueAt(0, 0));
        assertEquals(3, model.getValueAt(1, 0));

        model.applyFilter(result -> true);

        assertEquals(1, model.getValueAt(0, 0));
        assertEquals(2, model.getValueAt(1, 0));
        assertEquals(3, model.getValueAt(2, 0));
    }

    @Test
    void resetsRequestIdsWhenCleared() {
        FuzzerResultsTableModel model = new FuzzerResultsTableModel();
        model.addResult(new AttackResult("Header", "one", null, null), true);

        model.clear();
        model.addResult(new AttackResult("Header", "two", null, null), true);

        assertEquals(1, model.getValueAt(0, 0));
    }

    @Test
    void urlValidationLayoutSeparatesMetadataFromPayloadValue() {
        FuzzerResultsTableModel model = new FuzzerResultsTableModel(FuzzerResultsTableModel.TableLayout.URL_VALIDATION);
        model.addResult(new AttackResult(
            "URL Validation",
            "http://127.0.0.1/",
            "{INJECT} (origin header)",
            "CORS",
            "Intruder's",
            null,
            null
        ), true);

        assertEquals("{INJECT} (origin header)", model.getValueAt(0, 1));
        assertEquals("CORS", model.getValueAt(0, 2));
        assertEquals("Intruder's", model.getValueAt(0, 3));
        assertEquals("http://127.0.0.1/", model.getValueAt(0, 4));
    }

    @Test
    void idorLayoutSeparatesPhasePlaybookAndVariant() {
        FuzzerResultsTableModel model = new FuzzerResultsTableModel(FuzzerResultsTableModel.TableLayout.IDOR);
        model.addResult(new AttackResult(
            "IDOR",
            "path-authorized query-target",
            "Cross Source",
            "idor.hybrid.cross_source_conflicts",
            null,
            null,
            null
        ), true);

        assertEquals("Cross Source", model.getValueAt(0, 1));
        assertEquals("idor.hybrid.cross_source_conflicts", model.getValueAt(0, 2));
        assertEquals("path-authorized query-target", model.getValueAt(0, 3));
    }

    @Test
    void coverageSweepPayloadComesFirstAndHostIsParsedFromTarget() {
        FuzzerResultsTableModel model = new FuzzerResultsTableModel(FuzzerResultsTableModel.TableLayout.COVERAGE_SWEEP);
        String target = "GET https://dfyql-ro.sports.yahoo.com/v2/contestsFilteredWeb?lang=en-US&region=US&device=desktop&sport=mlb";
        model.addResult(new AttackResult("Coverage Sweep", "control", target,
            "Unauthenticated Control", "LIKELY PUBLIC", null, null), true);

        assertEquals("Payload", model.getColumnName(1));
        assertEquals("control", model.getValueAt(0, 1));
        assertEquals("Host", model.getColumnName(2));
        assertEquals("dfyql-ro.sports.yahoo.com", model.getValueAt(0, 2));
    }

    @Test
    void coverageSweepTextColumnsRetainFullValues() {
        FuzzerResultsTableModel model = new FuzzerResultsTableModel(FuzzerResultsTableModel.TableLayout.COVERAGE_SWEEP);
        String family = "Unauthenticated Control With Detailed Context";
        String signal = "BYPASS?: authenticated 200 -> anonymous 403 -> probe 200";
        String payload = "Original request without authentication and the complete probe description";
        model.addResult(new AttackResult("Coverage Sweep", payload, "target", family, signal,
            null, null), true);

        assertEquals(family, model.getValueAt(0, 3));
        assertEquals(signal, model.getValueAt(0, 4));
        assertEquals(payload, model.getValueAt(0, 1));
    }

    @Test
    void throttleRetryIsLabeledWithoutChangingItsPayloadMetadata() {
        FuzzerResultsTableModel model = new FuzzerResultsTableModel();
        AttackResult original = new AttackResult("Header", "X-Forwarded-For: 127.0.0.1", null, null);
        AttackResult retry = AttackResult.throttleRetryOf(original, null, 2);

        model.addResult(retry, true);

        assertEquals("X-Forwarded-For: 127.0.0.1", retry.getPayload());
        assertEquals("X-Forwarded-For: 127.0.0.1 [throttle retry #2]", model.getValueAt(0, 2));
    }
}

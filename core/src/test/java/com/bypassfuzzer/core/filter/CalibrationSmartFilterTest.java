package com.bypassfuzzer.core.filter;

import com.bypassfuzzer.core.scan.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class CalibrationSmartFilterTest {
    private record Row(String getPayload, ControlRole getControlRole) implements ResultView {
        public int getStatusCode() { return 404; }
        public int getContentLength() { return 0; }
        public String getContentType() { return ""; }
        public String getSignal() { return ""; }
        public String getRequestHost() { return "127.0.0.1"; }
        public String getResponseText() { return ""; }
    }
    @Test void calibrationNeverConsumesCandidateRepeatSlotsEvenWhenShown() {
        var config = new FilterConfig();
        config.setSmartFilterEnabled(true);
        config.setSmartFilterRepeats(1);
        var filter = new SmartFilter(config);
        var calibration = new Row("control", ControlRole.WILDCARD);
        var first = new Row("first", ControlRole.NONE);
        var repeated = new Row("repeated", ControlRole.NONE);
        filter.track(calibration); filter.track(first); filter.track(repeated);
        assertTrue(filter.shouldShow(first));
        assertFalse(filter.shouldShow(repeated));
        assertTrue(filter.shouldShow(calibration));
        config.setShowCalibrationRequests(true);
        assertTrue(filter.shouldShow(first));
        assertTrue(filter.shouldShow(calibration));
    }
}

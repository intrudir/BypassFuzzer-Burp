package com.bypassfuzzer.burp.core.coverage;

import burp.api.montoya.MontoyaApi;
import com.bypassfuzzer.burp.http.RequestSender;

import static com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.request;

/** Exercises the real Sweep importer without requiring Burp's static request factories. */
public final class SweepEngineTestFactory {
    private SweepEngineTestFactory() { }

    public static CoverageSweepEngine importedEngine(MontoyaApi api, RequestSender sender) {
        return new CoverageSweepEngine(api, sender, new CoverageSweepProbeGenerator(),
            uri -> request(uri.getRawPath(), uri.getRawQuery(), "GET", null, ""));
    }
}

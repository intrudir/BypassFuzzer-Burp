package com.bypassfuzzer.core.scan;

/** Fields used by the master's result filters, independent of transport and storage. */
public interface ResultView {
    int getStatusCode();
    int getContentLength();
    String getContentType();
    String getPayload();
    String getSignal();
    String getRequestHost();
    String getResponseText();
}

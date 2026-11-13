package com.bypassfuzzer.core.scan;

/** Fields used by the master's result filters, independent of transport and storage. */
public interface ResultView {
    /** Legacy results without control metadata remain ordinary visible results. */
    default ControlRole getControlRole() { return ControlRole.NONE; }
    int getStatusCode();
    int getContentLength();
    String getContentType();
    String getPayload();
    String getSignal();
    String getRequestHost();
    String getResponseText();
}

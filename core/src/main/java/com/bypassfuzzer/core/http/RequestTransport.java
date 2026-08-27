package com.bypassfuzzer.core.http;

import java.time.Duration;

@FunctionalInterface
public interface RequestTransport extends AutoCloseable {
    HttpResponseData send(HttpRequestData request, Duration timeout) throws Exception;

    @Override
    default void close() throws Exception {
    }
}

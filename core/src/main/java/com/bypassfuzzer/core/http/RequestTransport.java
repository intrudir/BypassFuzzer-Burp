package com.bypassfuzzer.core.http;

import java.time.Duration;

@FunctionalInterface
public interface RequestTransport extends AutoCloseable {
    HttpResponseData send(HttpRequestData request, Duration timeout) throws Exception;

    /** Adapters with an outer traffic governor place the live gate inside its final send. */
    default HttpResponseData sendManaged(HttpRequestData request,Duration timeout,com.bypassfuzzer.core.scan.LiveRun run,long revision) throws Exception {
        return run==null ? send(request,timeout) : run.send(revision,request.origin().host(),() -> send(request,timeout));
    }
    @Override
    default void close() throws Exception {
    }
}

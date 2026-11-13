package com.bypassfuzzer.burp.http;

import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

public interface RequestSender {
    HttpResponse send(HttpRequest request);

    default HttpResponse send(HttpRequest request, BooleanSupplier shouldContinue) {
        return shouldContinue == null || shouldContinue.getAsBoolean() ? send(request) : null;
    }

    default HttpResponse send(HttpRequest request, HttpMode httpMode) {
        return send(request);
    }

    default HttpResponse send(HttpRequest request, HttpMode httpMode, BooleanSupplier shouldContinue) {
        return shouldContinue == null || shouldContinue.getAsBoolean() ? send(request, httpMode) : null;
    }

    HttpResponse send(HttpRequest request, long timeout, TimeUnit timeUnit);

    default HttpResponse send(HttpRequest request, long timeout, TimeUnit timeUnit,
                              BooleanSupplier shouldContinue) {
        return shouldContinue == null || shouldContinue.getAsBoolean()
            ? send(request, timeout, timeUnit) : null;
    }

    default HttpResponse send(HttpRequest request, HttpMode httpMode, long timeout, TimeUnit timeUnit) {
        return send(request, timeout, timeUnit);
    }

    default HttpResponse send(HttpRequest request, HttpMode httpMode, long timeout, TimeUnit timeUnit,
                              BooleanSupplier shouldContinue) {
        return shouldContinue == null || shouldContinue.getAsBoolean()
            ? send(request, httpMode, timeout, timeUnit) : null;
    }

    /** A null mode uses Burp's automatic protocol selection. */
    default HttpResponse sendWithOptionalMode(HttpRequest request, HttpMode httpMode,
                                              BooleanSupplier shouldContinue) {
        return httpMode == null ? send(request, shouldContinue)
            : send(request, httpMode, shouldContinue);
    }

    default HttpResponse sendWithOptionalMode(HttpRequest request, HttpMode httpMode,
                                              long timeout, TimeUnit timeUnit,
                                              BooleanSupplier shouldContinue) {
        return httpMode == null ? send(request, timeout, timeUnit, shouldContinue)
            : send(request, httpMode, timeout, timeUnit, shouldContinue);
    }
    /** Production adapters put the live gate after extension-wide admission. */
    default HttpResponse sendManaged(HttpRequest request,HttpMode mode,long timeout,TimeUnit unit,BooleanSupplier continuing,
        com.bypassfuzzer.core.scan.LiveRun run,long revision) {
        try {
            return run==null ? sendWithOptionalMode(request,mode,timeout,unit,continuing)
                : run.send(revision,request.httpService().host(),() -> sendWithOptionalMode(request,mode,timeout,unit,continuing));
        }catch(com.bypassfuzzer.core.scan.LiveRun.Reconfigured | java.util.concurrent.CancellationException error){throw error;}
        catch(Exception error){throw new java.util.concurrent.CompletionException(error);}
    }

}

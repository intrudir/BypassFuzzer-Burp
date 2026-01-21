package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.Arrays;
import java.util.List;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

public class VerbAttack implements AttackStrategy {
    private static final List<String> HTTP_METHODS = Arrays.asList(
        "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE",
        "PATCH", "INVENTED", "HACK"
    );

    private static final List<String> OVERRIDE_HEADERS = Arrays.asList(
        "X-HTTP-Method-Override",
        "X-HTTP-Method",
        "X-Method-Override"
    );

    @Override
    public void execute(MontoyaApi api, HttpRequest baseRequest, String targetUrl, Consumer<AttackResult> resultCallback, BooleanSupplier shouldContinue) {
        try {
            api.logging().logToOutput("Starting Verb Attack");
        } catch (Exception e) {
            return;
        }

        int count = 0;

        for (String method : HTTP_METHODS) {
            if (!shouldContinue.getAsBoolean()) {
                try {
                    api.logging().logToOutput("Verb Attack stopped by user");
                } catch (Exception e) {}
                return;
            }

            try {
                HttpRequest modifiedRequest = baseRequest.withMethod(method);
                HttpResponse response = api.http().sendRequest(modifiedRequest).response();
                resultCallback.accept(new AttackResult(getAttackType(), "Method: " + method, modifiedRequest, response));
                count++;
            } catch (NullPointerException e) {
                return;
            } catch (Exception e) {
                try {
                    api.logging().logToError("Verb attack error with method " + method + ": " + e.getMessage());
                } catch (Exception logError) {}
            }
        }

        for (String header : OVERRIDE_HEADERS) {
            for (String method : HTTP_METHODS) {
                if (!shouldContinue.getAsBoolean()) {
                    try {
                        api.logging().logToOutput("Verb Attack stopped by user");
                    } catch (Exception e) {}
                    return;
                }

                try {
                    HttpRequest modifiedRequest = baseRequest.withAddedHeader(header, method);
                    HttpResponse response = api.http().sendRequest(modifiedRequest).response();
                    String payload = header + ": " + method;
                    resultCallback.accept(new AttackResult(getAttackType(), payload, modifiedRequest, response));
                    count++;
                } catch (NullPointerException e) {
                    return;
                } catch (Exception e) {
                    try {
                        api.logging().logToError("Verb attack error with override " + header + "/" + method + ": " + e.getMessage());
                    } catch (Exception logError) {}
                }
            }
        }

        for (String baseMethod : Arrays.asList("POST", "PUT")) {
            for (String header : OVERRIDE_HEADERS) {
                for (String overrideMethod : Arrays.asList("GET", "DELETE", "PATCH")) {
                    if (!shouldContinue.getAsBoolean()) {
                        try {
                            api.logging().logToOutput("Verb Attack stopped by user");
                        } catch (Exception e) {}
                        return;
                    }

                    try {
                        HttpRequest modifiedRequest = baseRequest
                            .withMethod(baseMethod)
                            .withAddedHeader(header, overrideMethod);
                        HttpResponse response = api.http().sendRequest(modifiedRequest).response();
                        String payload = baseMethod + " + " + header + ": " + overrideMethod;
                        resultCallback.accept(new AttackResult(getAttackType(), payload, modifiedRequest, response));
                        count++;
                    } catch (NullPointerException e) {
                        return;
                    } catch (Exception e) {
                        try {
                            api.logging().logToError("Verb attack error: " + e.getMessage());
                        } catch (Exception logError) {}
                    }
                }
            }
        }

        try {
            api.logging().logToOutput("Verb Attack completed: " + count + " results sent");
        } catch (Exception e) {}
    }

    @Override
    public String getAttackType() {
        return "Verb";
    }
}

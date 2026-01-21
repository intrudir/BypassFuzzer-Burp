package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

public class TrailingDotAttack implements AttackStrategy {

    @Override
    public void execute(MontoyaApi api, HttpRequest baseRequest, String targetUrl, Consumer<AttackResult> resultCallback, BooleanSupplier shouldContinue) {
        try {
            api.logging().logToOutput("Starting Trailing Dot Attack");
        } catch (Exception e) {
            return;
        }

        if (!shouldContinue.getAsBoolean()) {
            try {
                api.logging().logToOutput("Trailing Dot Attack stopped before execution");
            } catch (Exception e) {}
            return;
        }

        try {
            String host = baseRequest.httpService().host();
            String hostWithDot = host + ".";
            HttpRequest modifiedRequest = baseRequest.withUpdatedHeader("Host", hostWithDot);
            HttpResponse response = api.http().sendRequest(modifiedRequest).response();
            String payload = "Host: " + hostWithDot;
            resultCallback.accept(new AttackResult(getAttackType(), payload, modifiedRequest, response));
            api.logging().logToOutput("Trailing Dot Attack completed: 1 result sent");
        } catch (NullPointerException e) {
            // API null, abort
        } catch (Exception e) {
            try {
                api.logging().logToError("Trailing dot attack error: " + e.getMessage());
            } catch (Exception logError) {}
        }
    }

    @Override
    public String getAttackType() {
        return "TrailingDot";
    }
}

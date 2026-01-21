package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.RateLimiter;

import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * Interface for different attack strategies (Header, Path, Verb, Protocol, etc).
 */
public interface AttackStrategy {

    /**
     * Execute the attack and send results to callback immediately.
     *
     * @param api Burp Montoya API
     * @param baseRequest The original HTTP request to modify
     * @param targetUrl The target URL
     * @param resultCallback Callback to send each result as it's generated
     * @param shouldContinue Supplier that returns false when attack should stop
     * @param rateLimiter Rate limiter for controlling request rate (can be null)
     */
    void execute(MontoyaApi api, HttpRequest baseRequest, String targetUrl, Consumer<AttackResult> resultCallback, BooleanSupplier shouldContinue, RateLimiter rateLimiter);

    /**
     * Get the name of this attack type.
     *
     * @return Attack type name (e.g., "Header Attack", "Path Attack")
     */
    String getAttackType();
}

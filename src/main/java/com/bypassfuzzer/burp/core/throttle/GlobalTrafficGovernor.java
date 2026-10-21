package com.bypassfuzzer.burp.core.throttle;

import burp.api.montoya.http.message.requests.HttpRequest;
import java.util.function.LongSupplier;

/** Montoya boundary for extension-wide shared traffic admission. */
public final class GlobalTrafficGovernor extends com.bypassfuzzer.core.throttle.GlobalTrafficGovernor<HttpRequest> {
    public GlobalTrafficGovernor() { super(HostThrottleCoordinator::hostKey); }
    GlobalTrafficGovernor(LongSupplier clock) { super(HostThrottleCoordinator::hostKey, clock); }
}

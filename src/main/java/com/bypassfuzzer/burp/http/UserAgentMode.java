package com.bypassfuzzer.burp.http;

/** User-Agent behavior applied to generated requests in every attack mode. */
public enum UserAgentMode {
    DISABLED,
    SYNTHETIC,
    BROWSER_LIKE
}

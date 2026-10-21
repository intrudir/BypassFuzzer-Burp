package com.bypassfuzzer.burp.core.filter;
import com.bypassfuzzer.core.filter.FilterConfig;
import com.bypassfuzzer.burp.core.attacks.AttackResult;

/** Burp result adapter; filter rules and state live in core. */
public class SmartFilter extends com.bypassfuzzer.core.filter.SmartFilter implements ResponseFilter {
    public SmartFilter(FilterConfig config) { super(config); }
    @Override public boolean shouldShow(AttackResult result) { return super.shouldShow(result); }
}

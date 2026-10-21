package com.bypassfuzzer.burp.core.filter;
import com.bypassfuzzer.core.filter.FilterConfig;
import com.bypassfuzzer.burp.core.attacks.AttackResult;

/** Burp result adapter; filter rules and state live in core. */
public class ManualFilter extends com.bypassfuzzer.core.filter.ManualFilter implements ResponseFilter {
    public ManualFilter(FilterConfig config) { super(config); }
    @Override public boolean shouldShow(AttackResult result) { return super.shouldShow(result); }
}

package com.bypassfuzzer.burp.core.filter;

import java.util.HashSet;
import java.util.Set;

/**
 * Configuration for filtering attack results.
 */
public class FilterConfig {
    // Smart filter settings
    private boolean smartFilterEnabled = false;
    private int smartFilterRepeats = 10;

    // Manual filter settings
    private boolean manualFilterEnabled = false;
    private Set<Integer> hiddenStatusCodes = new HashSet<>();
    private Set<Integer> shownStatusCodes = new HashSet<>();
    private Integer minContentLength = null;
    private Integer maxContentLength = null;
    private Set<Integer> hiddenContentLengths = new HashSet<>();
    private Set<Integer> shownContentLengths = new HashSet<>();
    private String contentTypeFilter = null;
    private String hostContainsFilter = null;
    private String payloadContainsFilter = null;
    private String signalContainsFilter = null;
    private boolean signalContainsRegex = false;
    private String responseContainsFilter = null;
    private boolean responseContainsRegex = false;
    private boolean responseMatchInverted = false;

    public boolean isSmartFilterEnabled() {
        return smartFilterEnabled;
    }

    public void setSmartFilterEnabled(boolean enabled) {
        this.smartFilterEnabled = enabled;
    }

    public int getSmartFilterRepeats() {
        return smartFilterRepeats;
    }

    public void setSmartFilterRepeats(int smartFilterRepeats) {
        this.smartFilterRepeats = smartFilterRepeats;
    }

    public boolean isManualFilterEnabled() {
        return manualFilterEnabled;
    }

    public void setManualFilterEnabled(boolean enabled) {
        this.manualFilterEnabled = enabled;
    }

    public Set<Integer> getHiddenStatusCodes() {
        return hiddenStatusCodes;
    }

    public void setHiddenStatusCodes(Set<Integer> codes) {
        this.hiddenStatusCodes = codes;
    }

    public Set<Integer> getShownStatusCodes() {
        return shownStatusCodes;
    }

    public void setShownStatusCodes(Set<Integer> codes) {
        this.shownStatusCodes = codes;
    }

    public Integer getMinContentLength() {
        return minContentLength;
    }

    public void setMinContentLength(Integer min) {
        this.minContentLength = min;
    }

    public Integer getMaxContentLength() {
        return maxContentLength;
    }

    public void setMaxContentLength(Integer max) {
        this.maxContentLength = max;
    }

    public Set<Integer> getHiddenContentLengths() {
        return hiddenContentLengths;
    }

    public void setHiddenContentLengths(Set<Integer> lengths) {
        this.hiddenContentLengths = lengths;
    }

    public Set<Integer> getShownContentLengths() {
        return shownContentLengths;
    }

    public void setShownContentLengths(Set<Integer> lengths) {
        this.shownContentLengths = lengths;
    }

    public String getContentTypeFilter() {
        return contentTypeFilter;
    }

    public void setContentTypeFilter(String filter) {
        this.contentTypeFilter = filter;
    }

    public String getHostContainsFilter() {
        return hostContainsFilter;
    }

    public void setHostContainsFilter(String filter) {
        this.hostContainsFilter = filter;
    }

    public String getPayloadContainsFilter() {
        return payloadContainsFilter;
    }

    public void setPayloadContainsFilter(String filter) {
        this.payloadContainsFilter = filter;
    }

    public String getSignalContainsFilter() {
        return signalContainsFilter;
    }

    public void setSignalContainsFilter(String filter) {
        this.signalContainsFilter = filter;
    }

    public boolean isSignalContainsRegex() {
        return signalContainsRegex;
    }

    public void setSignalContainsRegex(boolean signalContainsRegex) {
        this.signalContainsRegex = signalContainsRegex;
    }

    public String getResponseContainsFilter() {
        return responseContainsFilter;
    }

    public void setResponseContainsFilter(String filter) {
        this.responseContainsFilter = filter;
    }

    public boolean isResponseContainsRegex() {
        return responseContainsRegex;
    }

    public void setResponseContainsRegex(boolean responseContainsRegex) {
        this.responseContainsRegex = responseContainsRegex;
    }

    public boolean isResponseMatchInverted() {
        return responseMatchInverted;
    }

    public void setResponseMatchInverted(boolean responseMatchInverted) {
        this.responseMatchInverted = responseMatchInverted;
    }
}

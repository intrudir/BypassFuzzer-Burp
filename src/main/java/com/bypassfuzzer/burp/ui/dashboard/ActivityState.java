package com.bypassfuzzer.burp.ui.dashboard;

public enum ActivityState {
    IDLE("Idle"),
    PREPARING("Preparing"),
    RUNNING("Running"),
    RETRYING("Retrying"),
    PAUSED("Paused"),
    STOPPING("Stopping"),
    STOPPED("Stopped"),
    COMPLETED("Completed"),
    FAILED("Failed"),
    DISPOSED("Closed");

    private final String label;

    ActivityState(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }

    public boolean active() {
        return this == PREPARING || this == RUNNING || this == RETRYING
            || this == PAUSED || this == STOPPING;
    }
}

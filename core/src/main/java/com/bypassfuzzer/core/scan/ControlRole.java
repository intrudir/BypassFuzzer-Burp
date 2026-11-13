package com.bypassfuzzer.core.scan;

public enum ControlRole {
    NONE, ORIGINAL, AUTHORIZED, TARGET, WILDCARD;

    public boolean isCalibration() { return this == WILDCARD; }
}

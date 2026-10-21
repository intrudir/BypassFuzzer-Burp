package com.bypassfuzzer.core.http;

import java.util.Objects;

public final class LocatedParameter {

    private final String name;
    private final String value;
    private final ParameterLocation location;
    private final String path;
    private final int occurrence;

    public LocatedParameter(String name, String value, ParameterLocation location) {
        this(name, value, location, name, -1);
    }

    public LocatedParameter(String name, String value, ParameterLocation location, String path, int occurrence) {
        this.name = name;
        this.value = value;
        this.location = location;
        this.path = path == null || path.isBlank() ? name : path;
        this.occurrence = occurrence;
    }

    public String name() {
        return name;
    }

    public String value() {
        return value;
    }

    public ParameterLocation location() {
        return location;
    }

    public String path() {
        return path;
    }

    public int occurrence() {
        return occurrence;
    }

    public boolean isBody() {
        return location == ParameterLocation.BODY;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof LocatedParameter parameter)) {
            return false;
        }
        return Objects.equals(name, parameter.name)
            && Objects.equals(value, parameter.value)
            && location == parameter.location;
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, value, location);
    }

    @Override
    public String toString() {
        return "LocatedParameter{"
            + "name='" + name + '\''
            + ", value='" + value + '\''
            + ", location=" + location
            + ", path='" + path + '\''
            + ", occurrence=" + occurrence
            + '}';
    }
}

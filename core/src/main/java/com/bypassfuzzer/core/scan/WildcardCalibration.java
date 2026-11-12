package com.bypassfuzzer.core.scan;

import com.bypassfuzzer.core.http.*;
import java.util.*;

/** Shared sibling control generation and conservative response comparison. */
public final class WildcardCalibration {
    private WildcardCalibration() { }
    public enum Assessment { MATCH, DIFFERENT, UNAVAILABLE, DISABLED }
    public static boolean eligible(String method) { return Set.of("GET", "HEAD").contains(method.toUpperCase(Locale.ROOT)); }
    public static <Q> Q control(Q seed, RequestAccess<Q> access) {
        String url = access.url(seed);
        int start = url.indexOf('/', url.indexOf("://") + 3);
        String target = start < 0 ? "/" : url.substring(start);
        int query = target.indexOf('?');
        String path = query < 0 ? target : target.substring(0, query);
        String sibling = path.substring(0, path.lastIndexOf('/') + 1) + "__bf_control_" + UUID.randomUUID().toString().replace("-", "");
        return access.withPath(seed, sibling + (query < 0 ? "" : target.substring(query)));
    }
    public static Long contentLength(String value) {
        try { long length = Long.parseLong(value.trim()); return length < 0 ? null : length; }
        catch (RuntimeException error) { return null; }
    }
    public static Assessment compare(String method, SweepClassifier.Response control, SweepClassifier.Response candidate,
                                     Set<Integer> throttleCodes) {
        if (control == null || candidate == null || throttleCodes.contains(control.statusCode())
            || throttleCodes.contains(candidate.statusCode())) return Assessment.UNAVAILABLE;
        Long a = eligible(method) && method.equalsIgnoreCase("HEAD") ? control.declaredLength() : Long.valueOf(control.contentLength());
        Long b = method.equalsIgnoreCase("HEAD") ? candidate.declaredLength() : Long.valueOf(candidate.contentLength());
        if (a == null || b == null) return Assessment.UNAVAILABLE;
        return control.statusCode() == candidate.statusCode() && media(control.contentType()).equals(media(candidate.contentType()))
            && Math.abs(a - b) <= 50 ? Assessment.MATCH : Assessment.DIFFERENT;
    }
    private static String media(String type) { return type == null ? "" : type.split(";", 2)[0].trim().toLowerCase(Locale.ROOT); }
}

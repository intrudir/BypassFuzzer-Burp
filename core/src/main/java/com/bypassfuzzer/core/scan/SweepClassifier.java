package com.bypassfuzzer.core.scan;

import com.bypassfuzzer.core.http.HttpResponseData;

public final class SweepClassifier {

    public record Response(int statusCode, int contentLength, String contentType, Long declaredLength) {
        public Response(int statusCode, int contentLength, String contentType) { this(statusCode, contentLength, contentType, null); }
    }
    public static Response response(HttpResponseData value) {
        return value == null ? null : new Response(value.statusCode(), value.bodyLength(), value.firstHeader("Content-Type").orElse(""), WildcardCalibration.contentLength(value.firstHeader("Content-Length").orElse("")));
    }
    public record Baseline(int statusCode, int contentLength, String contentType) { }

    public static final String LIKELY_PUBLIC_PREFIX = "LIKELY PUBLIC";
    public static final String LIKELY_UNAUTHENTICATED_BYPASS_PREFIX = "LIKELY UNAUTHENTICATED BYPASS";
    public static final String BYPASS_PREFIX = "BYPASS?";

    private SweepClassifier() {
    }

    public static boolean isInteresting(Baseline candidate, Response controlResponse, Response probeResponse) {
        if (candidate == null || probeResponse == null) {
            return false;
        }

        int probeStatus = probeResponse.statusCode();
        if (isClientError(probeStatus)) {
            return false;
        }

        int baselineStatus = controlResponse == null ? candidate.statusCode() : controlResponse.statusCode();
        if (isBlocked(baselineStatus) && (isSuccess(probeStatus) || isRedirect(probeStatus))) {
            return true;
        }
        if (isBlocked(baselineStatus) && !isBlocked(probeStatus)) {
            return true;
        }

        String baselineType = controlResponse == null ? candidate.contentType() : contentType(controlResponse);
        String probeType = contentType(probeResponse);
        if (!blank(baselineType) && !baselineType.equalsIgnoreCase(probeType)) {
            return true;
        }

        int baselineLength = controlResponse == null ? candidate.contentLength() : bodyLength(controlResponse);
        return Math.abs(bodyLength(probeResponse) - baselineLength) >= 100;
    }

    public static String signal(Baseline candidate, Response controlResponse, Response probeResponse) {
        if (candidate == null || probeResponse == null) {
            return "";
        }

        int probeStatus = probeResponse.statusCode();
        if (isClientError(probeStatus)) {
            return "";
        }

        int baselineStatus = controlResponse == null ? candidate.statusCode() : controlResponse.statusCode();
        if (isBlocked(baselineStatus) && !isBlocked(probeStatus)) {
            return baselineStatus + " -> " + probeStatus;
        }

        String baselineType = controlResponse == null ? candidate.contentType() : contentType(controlResponse);
        String probeType = contentType(probeResponse);
        if (!blank(baselineType) && !baselineType.equalsIgnoreCase(probeType)) {
            return "Content-Type " + baselineType + " -> " + (blank(probeType) ? "-" : probeType);
        }

        int baselineLength = controlResponse == null ? candidate.contentLength() : bodyLength(controlResponse);
        int delta = bodyLength(probeResponse) - baselineLength;
        if (Math.abs(delta) >= 100) {
            return "Length " + (delta > 0 ? "+" : "") + delta;
        }

        return "";
    }

    public static String unauthenticatedControlSignal(Baseline candidate,
                                                       Response anonymousResponse) {
        if (candidate == null || anonymousResponse == null || !isSuccess(anonymousResponse.statusCode())) {
            return "";
        }

        int authenticatedStatus = candidate.statusCode();
        if (!isSuccess(authenticatedStatus)) {
            return "";
        }

        String authenticatedType = normalizeContentType(candidate.contentType());
        String anonymousType = normalizeContentType(contentType(anonymousResponse));
        if (!blank(authenticatedType) && !blank(anonymousType)
            && !authenticatedType.equalsIgnoreCase(anonymousType)) {
            return "";
        }

        return LIKELY_PUBLIC_PREFIX + ": authenticated " + authenticatedStatus
            + " -> unauthenticated " + anonymousResponse.statusCode();
    }

    public static String unauthenticatedMutationSignal(Response anonymousControl,
                                                        Response probeResponse) {
        if (anonymousControl == null || probeResponse == null || !isBlocked(anonymousControl.statusCode())) {
            return "";
        }
        int probeStatus = probeResponse.statusCode();
        if (!isSuccess(probeStatus)) {
            return "";
        }
        return LIKELY_UNAUTHENTICATED_BYPASS_PREFIX + ": "
            + anonymousControl.statusCode() + " -> " + probeStatus;
    }

    public static String authenticatedBypassSignal(Baseline candidate,
                                                   Response anonymousControl,
                                                   Response probeResponse) {
        if (candidate == null || anonymousControl == null || probeResponse == null
            || !isSuccess(candidate.statusCode())
            || !isAuthBoundary(anonymousControl.statusCode())
            || !isSuccess(probeResponse.statusCode())) {
            return "";
        }

        String confidence = isStrongAuthBoundary(anonymousControl.statusCode()) ? "" : " (weak)";
        return BYPASS_PREFIX + confidence + ": authenticated " + candidate.statusCode()
            + " -> anonymous " + anonymousControl.statusCode()
            + " -> probe " + probeResponse.statusCode();
    }

    private static boolean isBlocked(int status) {
        return status == 401 || status == 403;
    }

    private static boolean isSuccess(int status) {
        return status >= 200 && status < 300;
    }

    private static boolean isRedirect(int status) {
        return status >= 300 && status < 400;
    }

    private static boolean isClientError(int status) {
        return status >= 400 && status < 500;
    }

    private static boolean isAuthBoundary(int status) {
        return isRedirect(status) || isClientError(status);
    }

    private static boolean isStrongAuthBoundary(int status) {
        return status == 401 || status == 403 || isRedirect(status);
    }

    private static int bodyLength(Response response) {
        return response == null ? 0 : response.contentLength();
    }

    private static String contentType(Response response) {
        return response == null ? "" : response.contentType();
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }

    private static String normalizeContentType(String value) {
        return blank(value) ? "" : value.split(";", 2)[0].trim();
    }
}

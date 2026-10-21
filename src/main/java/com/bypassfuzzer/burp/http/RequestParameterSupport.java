package com.bypassfuzzer.burp.http;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.core.http.LocatedParameter;
import com.bypassfuzzer.core.http.RequestBodyFormat;
import java.util.List;
import java.util.Map;

/** Montoya boundary for the master's shared parameter extraction and body conversion. */
public final class RequestParameterSupport {
    private static final CoreRequestAdapter ADAPTER = new CoreRequestAdapter();
    private RequestParameterSupport() { }
    public static boolean supportsBody(String method) {
        return com.bypassfuzzer.core.http.RequestParameterSupport.supportsBody(method);
    }
    public static String extractUrlEncodedBody(HttpRequest request) {
        return com.bypassfuzzer.core.http.RequestParameterSupport.extractUrlEncodedBody(ADAPTER.fromMontoya(request));
    }
    public static Map<String, String> extractCombinedParameters(HttpRequest request) {
        return com.bypassfuzzer.core.http.RequestParameterSupport.extractCombinedParameters(ADAPTER.fromMontoya(request));
    }
    public static List<LocatedParameter> extractLocatedParameters(HttpRequest request) {
        return com.bypassfuzzer.core.http.RequestParameterSupport.extractLocatedParameters(ADAPTER.fromMontoya(request));
    }
    public static HttpRequest prepareForBodyFormat(HttpRequest request, String method) {
        return ADAPTER.toMontoya(request, com.bypassfuzzer.core.http.RequestParameterSupport.prepareForBodyFormat(ADAPTER.fromMontoya(request), method));
    }
    public static HttpRequest applyBodyFormat(HttpRequest request, Map<String, String> params, RequestBodyFormat format) {
        return ADAPTER.toMontoya(request, com.bypassfuzzer.core.http.RequestParameterSupport.applyBodyFormat(ADAPTER.fromMontoya(request), params, format));
    }
    public static HttpRequest applyBodyFormat(HttpRequest request, List<LocatedParameter> params, RequestBodyFormat format) {
        return ADAPTER.toMontoya(request, com.bypassfuzzer.core.http.RequestParameterSupport.applyBodyFormat(ADAPTER.fromMontoya(request), params, format));
    }
    public static HttpRequest replaceParameterName(HttpRequest request, LocatedParameter parameter, String newName) {
        return ADAPTER.toMontoya(request, com.bypassfuzzer.core.http.RequestParameterSupport.replaceParameterName(ADAPTER.fromMontoya(request), parameter, newName));
    }
    public static HttpRequest replaceParameterValue(HttpRequest request, LocatedParameter parameter, String newValue) {
        return ADAPTER.toMontoya(request, com.bypassfuzzer.core.http.RequestParameterSupport.replaceParameterValue(ADAPTER.fromMontoya(request), parameter, newValue));
    }
    public static HttpRequest replaceJsonParameterValueWithJson(HttpRequest request, LocatedParameter parameter, String rawJsonValue) {
        return ADAPTER.toMontoya(request, com.bypassfuzzer.core.http.RequestParameterSupport.replaceJsonParameterValueWithJson(ADAPTER.fromMontoya(request), parameter, rawJsonValue));
    }
    public static HttpRequest replaceJsonParameterValuePreservingRawJson(HttpRequest request, LocatedParameter parameter, String rawJsonValue) {
        return ADAPTER.toMontoya(request, com.bypassfuzzer.core.http.RequestParameterSupport.replaceJsonParameterValuePreservingRawJson(ADAPTER.fromMontoya(request), parameter, rawJsonValue));
    }
    public static HttpRequest replaceJsonParameterWithDuplicateKeys(HttpRequest request, LocatedParameter parameter, String firstRawJsonValue, String secondRawJsonValue) {
        return ADAPTER.toMontoya(request, com.bypassfuzzer.core.http.RequestParameterSupport.replaceJsonParameterWithDuplicateKeys(ADAPTER.fromMontoya(request), parameter, firstRawJsonValue, secondRawJsonValue));
    }
    public static HttpRequest moveQueryToBody(HttpRequest request, String method) {
        return ADAPTER.toMontoya(request, com.bypassfuzzer.core.http.RequestParameterSupport.moveQueryToBody(ADAPTER.fromMontoya(request), method));
    }
    public static HttpRequest moveBodyToQuery(HttpRequest request, String method, String bodyParams) {
        return ADAPTER.toMontoya(request, com.bypassfuzzer.core.http.RequestParameterSupport.moveBodyToQuery(ADAPTER.fromMontoya(request), method, bodyParams));
    }
    public static HttpRequest putParamsInBoth(HttpRequest request, String method, String params) {
        return ADAPTER.toMontoya(request, com.bypassfuzzer.core.http.RequestParameterSupport.putParamsInBoth(ADAPTER.fromMontoya(request), method, params));
    }
    public static Map<String, String> parseBodyParameters(String body, String contentType) {
        return com.bypassfuzzer.core.http.RequestParameterSupport.parseBodyParameters(body, contentType);
    }
    public static String renderUrlEncoded(Map<String, String> params) {
        return com.bypassfuzzer.core.http.RequestParameterSupport.renderUrlEncoded(params);
    }
    public static String renderUrlEncoded(List<LocatedParameter> params) {
        return com.bypassfuzzer.core.http.RequestParameterSupport.renderUrlEncoded(params);
    }
    public static String renderJson(Map<String, String> params) {
        return com.bypassfuzzer.core.http.RequestParameterSupport.renderJson(params);
    }
    public static String renderJson(List<LocatedParameter> params) {
        return com.bypassfuzzer.core.http.RequestParameterSupport.renderJson(params);
    }
    public static String renderXml(Map<String, String> params) {
        return com.bypassfuzzer.core.http.RequestParameterSupport.renderXml(params);
    }
    public static String renderXml(List<LocatedParameter> params) {
        return com.bypassfuzzer.core.http.RequestParameterSupport.renderXml(params);
    }
    public static String renderMultipart(Map<String, String> params, String boundary) {
        return com.bypassfuzzer.core.http.RequestParameterSupport.renderMultipart(params, boundary);
    }
    public static String renderMultipart(List<LocatedParameter> params, String boundary) {
        return com.bypassfuzzer.core.http.RequestParameterSupport.renderMultipart(params, boundary);
    }
}

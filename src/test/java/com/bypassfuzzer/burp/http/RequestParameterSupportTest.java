package com.bypassfuzzer.burp.http;
import com.bypassfuzzer.core.http.RequestBodyFormat;
import com.bypassfuzzer.core.http.ParameterLocation;
import com.bypassfuzzer.core.http.LocatedParameter;

import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.request;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RequestParameterSupportTest {

    @Test
    void extractsCombinedParametersMergesQueryAndBodyWithBodyTakingPrecedence() {
        HttpRequest request = request(
            "/admin",
            "debug=query&source=query",
            "POST",
            "application/x-www-form-urlencoded",
            "debug=body&role=admin"
        );

        assertEquals(
            Map.of("debug", "body", "source", "query", "role", "admin"),
            RequestParameterSupport.extractCombinedParameters(request)
        );
    }

    @Test
    void extractsLocatedParametersFromQueryAndBody() {
        HttpRequest request = request("/admin", "debug=1", "POST", "application/json", "{\"role\":\"admin\"}");

        List<LocatedParameter> params = RequestParameterSupport.extractLocatedParameters(request);

        assertTrue(params.contains(new LocatedParameter("debug", "1", ParameterLocation.QUERY)));
        assertTrue(params.contains(new LocatedParameter("role", "admin", ParameterLocation.BODY)));
    }

    @Test
    void extractsCombinedParametersFromComplexJsonBody() {
        HttpRequest request = request(
            "/admin",
            "source=query",
            "POST",
            "application/json",
            "{\"role\":\"admin\",\"enabled\":true,\"meta\":{\"team\":\"red\"},\"tags\":[\"a\",\"b\"]}"
        );

        assertEquals(
            Map.of(
                "source", "query",
                "role", "admin",
                "enabled", "true",
                "meta", "{\"team\":\"red\"}",
                "tags", "[\"a\",\"b\"]"
            ),
            RequestParameterSupport.extractCombinedParameters(request)
        );
    }

    @Test
    void appliesJsonBodyFormat() {
        HttpRequest request = request("/admin", "", "POST", "application/x-www-form-urlencoded", "debug=true");

        HttpRequest updated = RequestParameterSupport.applyBodyFormat(
            request,
            Map.of("debug", "true", "role", "admin"),
            RequestBodyFormat.JSON
        );

        assertEquals("application/json", updated.headerValue("Content-Type"));
        assertTrue(updated.bodyToString().contains("\"debug\":\"true\""));
        assertTrue(updated.bodyToString().contains("\"role\":\"admin\""));
    }

    @Test
    void appliesBodyFormatPreservingDuplicateParameters() {
        HttpRequest request = request("/admin", "", "POST", "application/json", "{\"debug\":\"true\"}");

        HttpRequest updated = RequestParameterSupport.applyBodyFormat(
            request,
            List.of(
                new LocatedParameter("debug", "one", ParameterLocation.BODY, "debug", 0),
                new LocatedParameter("debug", "two", ParameterLocation.BODY, "debug", 1)
            ),
            RequestBodyFormat.JSON
        );

        assertEquals("application/json", updated.headerValue("Content-Type"));
        assertEquals("{\"debug\":\"one\",\"debug\":\"two\"}", updated.bodyToString());
    }

    @Test
    void appliesBodyFormatFlattensNestedPathsForConversion() {
        HttpRequest request = request("/admin", "", "POST", "application/xml", "<root/>");

        HttpRequest updated = RequestParameterSupport.applyBodyFormat(
            request,
            List.of(
                new LocatedParameter("role", "user", ParameterLocation.BODY, "/meta/role", -1),
                new LocatedParameter("role", "admin", ParameterLocation.BODY, "/users/0/role", -1),
                new LocatedParameter("role", "auditor", ParameterLocation.BODY, "/root[0]/users[0]/user[1]/role[0]", -1)
            ),
            RequestBodyFormat.MULTIPART
        );

        assertTrue(updated.bodyToString().contains("name=\"meta.role\""));
        assertTrue(updated.bodyToString().contains("name=\"users[0].role\""));
        assertTrue(updated.bodyToString().contains("name=\"users.user[1].role\""));
        assertTrue(!updated.bodyToString().contains("name=\"root[0].users[0].user[1].role[0]\""));
    }

    @Test
    void replacesQueryAndBodyParameters() {
        HttpRequest queryRequest = request("/admin", "debug=1&role=user", "GET", null, "");
        HttpRequest renamedQuery = RequestParameterSupport.replaceParameterName(
            queryRequest,
            new LocatedParameter("debug", "1", ParameterLocation.QUERY),
            "trace"
        );
        HttpRequest updatedQuery = RequestParameterSupport.replaceParameterValue(
            renamedQuery,
            new LocatedParameter("trace", "1", ParameterLocation.QUERY),
            "true"
        );

        assertEquals("/admin?trace=true&role=user", updatedQuery.path());

        HttpRequest bodyRequest = request("/admin", "", "POST", "application/x-www-form-urlencoded", "debug=1&role=user");

        HttpRequest renamedBody = RequestParameterSupport.replaceParameterName(
            bodyRequest,
            new LocatedParameter("debug", "1", ParameterLocation.BODY),
            "trace"
        );
        HttpRequest updatedBody = RequestParameterSupport.replaceParameterValue(
            renamedBody,
            new LocatedParameter("trace", "1", ParameterLocation.BODY),
            "true"
        );

        assertEquals("trace=true&role=user", updatedBody.bodyToString());
    }

    @Test
    void replacesJsonParametersWithoutCorruptingStructuredBodyContent() {
        HttpRequest bodyRequest = request(
            "/admin",
            "",
            "POST",
            "application/json",
            "{\"message\":\"say \\\"hi\\\"\",\"role\":\"user\",\"tags\":[\"a\",\"b\"]}"
        );

        HttpRequest renamedBody = RequestParameterSupport.replaceParameterName(
            bodyRequest,
            new LocatedParameter("role", "user", ParameterLocation.BODY),
            "trace"
        );
        HttpRequest updatedBody = RequestParameterSupport.replaceParameterValue(
            renamedBody,
            new LocatedParameter("trace", "user", ParameterLocation.BODY),
            "true"
        );

        assertEquals(
            "{\"message\":\"say \\\"hi\\\"\",\"trace\":\"true\",\"tags\":[\"a\",\"b\"]}",
            updatedBody.bodyToString()
        );
    }

    @Test
    void extractsNestedJsonParametersAndTargetsSpecificPath() {
        HttpRequest bodyRequest = request(
            "/admin",
            "",
            "POST",
            "application/json",
            "{\"meta\":{\"role\":\"user\"},\"users\":[{\"role\":\"admin\"}]}"
        );

        List<LocatedParameter> params = RequestParameterSupport.extractLocatedParameters(bodyRequest);

        assertEquals(
            List.of("/meta/role", "/users/0/role"),
            params.stream().filter(LocatedParameter::isBody).map(LocatedParameter::path).collect(Collectors.toList())
        );

        HttpRequest renamedBody = RequestParameterSupport.replaceParameterName(
            bodyRequest,
            new LocatedParameter("role", "user", ParameterLocation.BODY, "/meta/role", -1),
            "trace"
        );
        HttpRequest updatedBody = RequestParameterSupport.replaceParameterValue(
            renamedBody,
            new LocatedParameter("trace", "user", ParameterLocation.BODY, "/meta/trace", -1),
            "true"
        );

        assertEquals("{\"meta\":{\"trace\":\"true\"},\"users\":[{\"role\":\"admin\"}]}", updatedBody.bodyToString());
    }

    @Test
    void replacesJsonParametersPreservingRawJsonEscapesWhenRequested() {
        HttpRequest bodyRequest = request(
            "/admin",
            "",
            "POST",
            "application/json",
            "{\"id\":\"550e8400-e29b-41d4-a716-446655440000\"}"
        );

        HttpRequest updatedBody = RequestParameterSupport.replaceJsonParameterValuePreservingRawJson(
            bodyRequest,
            new LocatedParameter("id", "550e8400-e29b-41d4-a716-446655440000", ParameterLocation.BODY, "/id", -1),
            "\"550e8400\\u002de29b\\u002d41d4\\u002da716\\u002d446655440000\""
        );

        assertEquals(
            "{\"id\":\"550e8400\\u002de29b\\u002d41d4\\u002da716\\u002d446655440000\"}",
            updatedBody.bodyToString()
        );
    }

    @Test
    void extractsAndReplacesXmlParameters() {
        HttpRequest bodyRequest = request(
            "/admin",
            "",
            "POST",
            "application/xml",
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><root><debug>false</debug><role>user</role></root>"
        );

        assertEquals(
            Map.of("debug", "false", "role", "user"),
            RequestParameterSupport.extractCombinedParameters(bodyRequest)
        );

        HttpRequest renamedBody = RequestParameterSupport.replaceParameterName(
            bodyRequest,
            new LocatedParameter("debug", "false", ParameterLocation.BODY),
            "trace"
        );
        HttpRequest updatedBody = RequestParameterSupport.replaceParameterValue(
            renamedBody,
            new LocatedParameter("trace", "false", ParameterLocation.BODY),
            "true"
        );

        assertTrue(updatedBody.bodyToString().contains("<trace>true</trace>"));
        assertTrue(updatedBody.bodyToString().contains("<role>user</role>"));
    }

    @Test
    void extractsAndReplacesMultipartParameters() {
        String boundary = "----Boundary123";
        String body =
            "--" + boundary + "\r\n" +
            "Content-Disposition: form-data; name=\"debug\"\r\n\r\n" +
            "false\r\n" +
            "--" + boundary + "\r\n" +
            "Content-Disposition: form-data; name=\"role\"\r\n\r\n" +
            "user\r\n" +
            "--" + boundary + "--\r\n";
        HttpRequest bodyRequest = request(
            "/admin",
            "",
            "POST",
            "multipart/form-data; boundary=\"" + boundary + "\"",
            body
        );

        assertEquals(
            Map.of("debug", "false", "role", "user"),
            RequestParameterSupport.extractCombinedParameters(bodyRequest)
        );

        HttpRequest renamedBody = RequestParameterSupport.replaceParameterName(
            bodyRequest,
            new LocatedParameter("debug", "false", ParameterLocation.BODY),
            "trace"
        );
        HttpRequest updatedBody = RequestParameterSupport.replaceParameterValue(
            renamedBody,
            new LocatedParameter("trace", "false", ParameterLocation.BODY),
            "true"
        );

        assertTrue(updatedBody.bodyToString().contains("name=\"trace\""));
        assertTrue(updatedBody.bodyToString().contains("\r\n\r\ntrue\r\n"));
        assertTrue(updatedBody.bodyToString().contains("name=\"role\""));
    }

    @Test
    void preservesDuplicateBodyParametersWhenExtractingAndReplacingSpecificOccurrence() {
        HttpRequest bodyRequest = request(
            "/admin",
            "",
            "POST",
            "application/x-www-form-urlencoded",
            "debug=one&debug=two&role=user"
        );

        List<LocatedParameter> params = RequestParameterSupport.extractLocatedParameters(bodyRequest);

        assertEquals(
            List.of(
                new LocatedParameter("debug", "one", ParameterLocation.BODY, "debug", 0),
                new LocatedParameter("debug", "two", ParameterLocation.BODY, "debug", 1),
                new LocatedParameter("role", "user", ParameterLocation.BODY, "role", 0)
            ),
            params
        );

        HttpRequest renamedBody = RequestParameterSupport.replaceParameterName(
            bodyRequest,
            new LocatedParameter("debug", "two", ParameterLocation.BODY, "debug", 1),
            "trace"
        );
        HttpRequest updatedBody = RequestParameterSupport.replaceParameterValue(
            renamedBody,
            new LocatedParameter("trace", "two", ParameterLocation.BODY, "trace", 0),
            "changed"
        );

        assertEquals("debug=one&trace=changed&role=user", updatedBody.bodyToString());
    }

    @Test
    void movesParametersBetweenQueryAndBody() {
        HttpRequest queryRequest = request("/admin", "debug=1&role=user", "GET", null, "");
        HttpRequest movedToBody = RequestParameterSupport.moveQueryToBody(queryRequest, "POST");
        assertEquals("/admin", movedToBody.path());
        assertEquals("debug=1&role=user", movedToBody.bodyToString());

        HttpRequest bodyRequest = request("/admin", "", "POST", "application/x-www-form-urlencoded", "debug=1&role=user");
        HttpRequest movedToQuery = RequestParameterSupport.moveBodyToQuery(bodyRequest, "GET", bodyRequest.bodyToString());

        assertEquals("/admin?debug=1&role=user", movedToQuery.path());
        assertEquals("", movedToQuery.bodyToString());
    }

    @Test
    void preparesQueryOnlyRequestForBodyFormatByDroppingTheQuery() {
        HttpRequest request = request("/admin", "debug=1&role=user", "GET", null, "");

        HttpRequest prepared = RequestParameterSupport.prepareForBodyFormat(request, "POST");

        assertEquals("POST", prepared.method());
        assertEquals("/admin", prepared.path());
        assertEquals("", prepared.query());
    }

    @Test
    void preservesDuplicateQueryParametersWhenExtractingLocatedParameters() {
        HttpRequest request = request("/admin", "debug=1&debug=2&role=user", "GET", null, "");

        List<LocatedParameter> params = RequestParameterSupport.extractLocatedParameters(request);

        assertEquals(
            List.of(
                new LocatedParameter("debug", "1", ParameterLocation.QUERY),
                new LocatedParameter("debug", "2", ParameterLocation.QUERY),
                new LocatedParameter("role", "user", ParameterLocation.QUERY)
            ),
            params
        );
    }

}

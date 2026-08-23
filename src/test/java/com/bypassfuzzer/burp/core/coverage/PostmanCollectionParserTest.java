package com.bypassfuzzer.burp.core.coverage;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PostmanCollectionParserTest {

    @Test
    void parsesNestedRequestsVariablesHeadersQueriesAndRawBodies() {
        String collection = """
            {
              "info":{"name":"Example","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
              "variable":[{"key":"host","value":"api.example.com"},{"key":"token","value":"secret"}],
              "auth":{"type":"bearer","bearer":[{"key":"token","value":"{{token}}"}]},
              "item":[{"name":"Folder","item":[
                {"name":"Create","request":{"method":"POST",
                  "header":[{"key":"X-Test","value":"yes"}],
                  "body":{"mode":"raw","raw":"{\\"name\\":\\"demo\\"}","options":{"raw":{"language":"json"}}},
                  "url":{"raw":"https://{{host}}/users?active=true","query":[{"key":"active","value":"true"}]}}},
                {"name":"Disabled","disabled":true,"request":{"method":"GET","url":"https://example.com/nope"}}
              ]}]
            }
            """;

        List<OpenApiOperation> operations = new PostmanCollectionParser().parse(collection, "");

        assertEquals(1, operations.size());
        OpenApiOperation operation = operations.get(0);
        assertEquals("POST", operation.method());
        assertEquals("https://api.example.com/users?active=true", operation.url());
        assertEquals("yes", operation.headers().get("X-Test"));
        assertEquals("Bearer secret", operation.headers().get("Authorization"));
        assertEquals("application/json", operation.headers().get("Content-Type"));
        assertEquals("{\"name\":\"demo\"}", operation.body());
    }

    @Test
    void importsUrlEncodedMultipartAndGraphqlContentTypes() {
        String collection = """
            {"info":{"schema":"https://schema.getpostman.com/json/collection/v2.0.0/collection.json"},"item":[
              {"request":{"method":"POST","url":"https://example.com/form","body":{"mode":"urlencoded","urlencoded":[
                {"key":"name","value":"a b"},{"key":"skip","value":"x","disabled":true}]}}},
              {"request":{"method":"POST","url":"https://example.com/upload","body":{"mode":"formdata","formdata":[
                {"key":"note","value":"hello","type":"text"},{"key":"photo","src":"/tmp/p.png","type":"file"}]}}},
              {"request":{"method":"POST","url":"https://example.com/graphql","body":{"mode":"graphql","graphql":
                {"query":"query { viewer { id } }","variables":"{\\"limit\\":1}"}}}}
            ]}
            """;

        List<OpenApiOperation> operations = new PostmanCollectionParser().parse(collection, "");

        assertEquals("application/x-www-form-urlencoded", operations.get(0).headers().get("Content-Type"));
        assertEquals("name=a+b", operations.get(0).body());
        assertTrue(operations.get(1).headers().get("Content-Type").startsWith("multipart/form-data; boundary="));
        assertTrue(operations.get(1).body().contains("name=\"note\""));
        assertTrue(operations.get(1).body().contains("filename=\"p.png\""));
        assertEquals("application/json", operations.get(2).headers().get("Content-Type"));
        assertTrue(operations.get(2).body().contains("viewer"));
    }

    @Test
    void resolvesRelativeAndUnresolvedVariableUrlsAgainstOverride() {
        String collection = """
            {"info":{"schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},"item":[
              {"request":{"method":"GET","url":"/v1/users"}},
              {"request":{"method":"GET","url":"{{missing}}/status"}}
            ]}
            """;

        List<OpenApiOperation> operations = new PostmanCollectionParser().parse(
            collection, "https://localhost:8443/api");

        assertEquals("https://localhost:8443/api/v1/users", operations.get(0).url());
        assertEquals("https://localhost:8443/api/{{missing}}/status", operations.get(1).url());
    }

    @Test
    void recognizesOnlyPostmanCollectionDocuments() {
        assertTrue(PostmanCollectionParser.looksLikePostmanCollection("""
            {"info":{"schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},"item":[]}
            """));
        assertFalse(PostmanCollectionParser.looksLikePostmanCollection("{\"openapi\":\"3.0.0\"}"));
    }
}

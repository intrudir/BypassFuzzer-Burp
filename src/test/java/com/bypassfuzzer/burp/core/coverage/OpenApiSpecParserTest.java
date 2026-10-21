package com.bypassfuzzer.burp.core.coverage;
import com.bypassfuzzer.core.input.OpenApiSpecParser;
import com.bypassfuzzer.core.input.OpenApiOperation;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OpenApiSpecParserTest {

    @Test
    void removesResponseControlCharactersBeforeParsingYaml() {
        String source = "\u0000openapi: 3.0.0\n"
            + "info:\n  title: News\u000Bfeed\n  version: 1.0.0\n"
            + "paths:\n  /items:\n    get:\n      responses: {}\n";

        List<OpenApiOperation> operations = new OpenApiSpecParser().parse(
            source, "index.html", "", "https://finance.mobile.yahoo.com/docs//newsfeedservice.yaml");

        assertEquals(1, operations.size());
        assertEquals("https://finance.mobile.yahoo.com/items", operations.get(0).url());
    }

    @Test
    void parsesYamlOperationsParametersAndJsonRequestBody() {
        String spec = """
            openapi: 3.0.3
            servers:
              - url: https://api.example.test/v1
            paths:
              /users/{id}:
                parameters:
                  - name: id
                    in: path
                    required: true
                    schema:
                      type: integer
                      example: 42
                get:
                  parameters:
                    - name: verbose
                      in: query
                      schema:
                        type: boolean
                        default: true
                post:
                  requestBody:
                    content:
                      application/json:
                        schema:
                          type: object
                          properties:
                            role:
                              type: string
                              example: admin
            """;

        List<OpenApiOperation> operations = new OpenApiSpecParser().parse(spec, "openapi.yaml");

        assertEquals(2, operations.size());
        OpenApiOperation get = operations.stream().filter(operation -> operation.method().equals("GET")).findFirst().orElseThrow();
        OpenApiOperation post = operations.stream().filter(operation -> operation.method().equals("POST")).findFirst().orElseThrow();
        assertEquals("https://api.example.test/v1/users/42?verbose=true", get.url());
        assertEquals("application/json", post.headers().get("Content-Type"));
        assertEquals("{\"role\":\"admin\"}", post.body());
    }

    @Test
    void replacesEmptyFormExampleWithGeneratedSchemaBody() {
        String spec = """
            openapi: 3.0.0
            servers: [{url: https://api.example.test}]
            paths:
              /oauth2/token:
                post:
                  requestBody:
                    content:
                      application/x-www-form-urlencoded:
                        example: {}
                        schema:
                          type: object
                          properties:
                            grant_type: {type: string, enum: [client_credentials]}
                            client_id: {type: string, example: your-client-id}
                            client_secret: {type: string, example: your-client-secret}
            """;

        OpenApiOperation operation = new OpenApiSpecParser().parse(spec, "openapi.yaml").get(0);

        assertEquals("application/x-www-form-urlencoded", operation.headers().get("Content-Type"));
        assertEquals("grant_type=client_credentials&client_id=your-client-id&client_secret=your-client-secret",
            operation.body());
    }

    @Test
    void supportsNamedExamplesAndMissingServers() {
        String spec = """
            openapi: 3.0.0
            paths:
              /profiles:
                post:
                  requestBody:
                    content:
                      application/json:
                        examples:
                          primary:
                            value: {email: named@example.com}
                        schema:
                          allOf:
                            - type: object
                              properties:
                                id: {type: string, format: uuid}
                            - type: object
                              properties:
                                enabled: {type: boolean}
            """;

        OpenApiOperation operation = new OpenApiSpecParser().parse(spec, "openapi.yaml").get(0);

        assertEquals("https://localhost/profiles", operation.url());
        assertEquals("{\"email\":\"named@example.com\"}", operation.body());
    }

    @Test
    void generatesBodiesFromComposedSchemasAndFormats() {
        String spec = """
            openapi: 3.0.0
            servers: [{url: https://api.example.test}]
            paths:
              /profiles:
                post:
                  requestBody:
                    content:
                      application/json:
                        schema:
                          allOf:
                            - type: object
                              properties:
                                id: {type: string, format: uuid}
                            - type: object
                              properties:
                                enabled: {type: boolean}
            """;

        OpenApiOperation operation = new OpenApiSpecParser().parse(spec, "openapi.yaml").get(0);

        assertEquals("{\"id\":\"00000000-0000-4000-8000-000000000000\",\"enabled\":true}",
            operation.body());
    }

    @Test
    void parsesSwaggerTwoAndAllowsBaseUrlOverride() {
        String spec = """
            {
              "swagger": "2.0",
              "host": "documented.example",
              "basePath": "/api",
              "schemes": ["https"],
              "paths": {"/health": {"get": {"responses": {"200": {"description": "ok"}}}}}
            }
            """;

        List<OpenApiOperation> documented = new OpenApiSpecParser().parse(spec, "swagger.json");
        List<OpenApiOperation> overridden = new OpenApiSpecParser().parse(spec, "swagger.json", "http://localhost:8080/base");

        assertEquals("https://documented.example/api/health", documented.get(0).url());
        assertEquals("http://localhost:8080/base/health", overridden.get(0).url());
        assertTrue(overridden.get(0).headers().isEmpty());
    }

    @Test
    void importsReferencedQueryHeaderCookieAndArrayParameters() {
        String spec = """
            openapi: 3.0.3
            servers: [{url: https://finance.mobile.yahoo.com}]
            components:
              parameters:
                RegionRef: {$ref: '#/components/parameters/Region'}
                Region:
                  name: region
                  in: query
                  examples:
                    primary: {value: US}
                Uuids:
                  name: uuids
                  in: query
                  schema:
                    type: array
                    items: {type: string, example: abc-123}
                Session:
                  name: session
                  in: cookie
                  schema: {type: string, default: token}
            paths:
              /dp/v2/homerun/newsitems:
                parameters:
                  - {$ref: '#/components/parameters/RegionRef'}
                  - {$ref: '#/components/parameters/Uuids'}
                get:
                  parameters:
                    - {$ref: '#/components/parameters/Session'}
                    - name: X-Client
                      in: header
                      content:
                        text/plain:
                          example: mobile
                          schema: {type: string, default: desktop}
            """;

        OpenApiOperation operation = new OpenApiSpecParser().parse(spec, "openapi.yaml").get(0);

        assertEquals("https://finance.mobile.yahoo.com/dp/v2/homerun/newsitems?region=US&uuids=abc-123",
            operation.url());
        assertEquals("mobile", operation.headers().get("X-Client"));
        assertEquals("session=token", operation.headers().get("Cookie"));
    }

    @Test
    void operationParametersOverridePathParametersAndRespectQueryStyle() {
        String spec = """
            openapi: 3.0.3
            servers: [{url: https://api.example.test}]
            paths:
              /search:
                parameters:
                  - name: fields
                    in: query
                    schema: {type: string, default: path-value}
                get:
                  parameters:
                    - name: fields
                      in: query
                      schema:
                        type: array
                        default: [one, two]
                    - name: compact
                      in: query
                      style: form
                      explode: false
                      schema:
                        type: array
                        default: [three, four]
            """;

        OpenApiOperation operation = new OpenApiSpecParser().parse(spec, "openapi.yaml").get(0);

        assertEquals("https://api.example.test/search?fields=one&fields=two&compact=three%2Cfour",
            operation.url());
    }

    @Test
    void resolvesRelativeAndImplicitServersAgainstUrlImportedSpec() {
        String relative = """
            openapi: 3.0.3
            servers: [{url: /api/v2}]
            paths: {/quotes: {get: {responses: {}}}}
            """;
        String implicit = """
            openapi: 3.0.3
            paths: {/health: {get: {responses: {}}}}
            """;

        OpenApiOperation relativeOperation = new OpenApiSpecParser().parse(relative, "openapi.yaml", "",
            "https://example.test/docs/openapi.yaml").get(0);
        OpenApiOperation implicitOperation = new OpenApiSpecParser().parse(implicit, "openapi.yaml", "",
            "https://example.test/docs/openapi.yaml").get(0);

        assertEquals("https://example.test/api/v2/quotes", relativeOperation.url());
        assertEquals("https://example.test/health", implicitOperation.url());
    }

    @Test
    void failsInsteadOfSilentlyDroppingUnresolvableParameters() {
        String spec = """
            openapi: 3.0.3
            servers: [{url: https://api.example.test}]
            paths:
              /search:
                get:
                  parameters:
                    - {$ref: '#/components/parameters/Missing'}
            """;

        IllegalArgumentException error = org.junit.jupiter.api.Assertions.assertThrows(
            IllegalArgumentException.class,
            () -> new OpenApiSpecParser().parse(spec, "openapi.yaml"));

        assertTrue(error.getMessage().contains("#/components/parameters/Missing"));
    }
}

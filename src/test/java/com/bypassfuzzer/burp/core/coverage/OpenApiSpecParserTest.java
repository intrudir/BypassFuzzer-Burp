package com.bypassfuzzer.burp.core.coverage;
import com.bypassfuzzer.core.input.OpenApiSpecParser;
import com.bypassfuzzer.core.input.OpenApiImportOptions;
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
    private static final String VARIABLE_SPEC = """
        openapi: 3.0.3
        servers: [{url: 'https://{tenant}.example.test/api', variables: {tenant: {default: demo}}}]
        paths:
          /tenants/{tenantId}/items:
            parameters:
              - {name: tenantId, in: path, required: true, schema: {type: string, default: sample}}
            get:
              parameters:
                - {name: required, in: query, required: true, schema: {type: string}}
                - {name: optional, in: query, schema: {type: string}}
                - {name: limit, in: query, schema: {type: integer, default: 10}}
                - {name: X-Tenant, in: header, example: '{{tenantId}}'}
                - {name: session, in: cookie, example: '{tenantId}'}
          /tenants/{tenantId}/reports:
            get:
              parameters:
                - {name: tenantId, in: path, required: true, example: other-sample}
        """;

    @Test
    void managedVariablesOverrideDefaultsAcrossOperationsAndEncodeEachLocation() {
        var settings = new OpenApiImportOptions(OpenApiImportOptions.ParameterPolicy.SOURCE_VALUES_ONLY,
            java.util.Map.of("tenant", "production", "tenantId", "acme/a b&c"));
        var operations = new OpenApiSpecParser().parse(VARIABLE_SPEC, "api.yaml", "", "", settings);

        assertEquals(2, operations.size());
        assertEquals("https://production.example.test/api/tenants/acme%2Fa%20b%26c/items?limit=10",
            operations.get(0).url());
        assertEquals("acme/a b&c", operations.get(0).headers().get("X-Tenant"));
        assertEquals("session=acme%2Fa+b%26c", operations.get(0).headers().get("Cookie"));
        assertEquals("https://production.example.test/api/tenants/acme%2Fa%20b%26c/reports",
            operations.get(1).url());
    }

    @Test
    void parameterModesRetainSourceValuesAndDistinguishRequiredFromOptional() {
        var parser = new OpenApiSpecParser();
        var source = parser.parse(VARIABLE_SPEC.replace("{{tenantId}}", "fixed").replace("{tenantId}", "fixed"),
            "api.yaml", "", "", new OpenApiImportOptions(
                OpenApiImportOptions.ParameterPolicy.SOURCE_VALUES_ONLY, java.util.Map.of())).get(0);
        assertTrue(source.url().endsWith("/items?limit=10"));
        for (var policy : java.util.List.of(OpenApiImportOptions.ParameterPolicy.REQUIRED_EMPTY,
            OpenApiImportOptions.ParameterPolicy.ALL_EMPTY)) {
            var operation = parser.parse(VARIABLE_SPEC, "api.yaml", "", "",
                new OpenApiImportOptions(policy, java.util.Map.of("tenantId", "live"))).get(0);
            assertTrue(operation.url().endsWith(policy == OpenApiImportOptions.ParameterPolicy.ALL_EMPTY
                ? "?required=&optional=&limit=10" : "?required=&limit=10"));
        }
        var required = parser.parse(VARIABLE_SPEC, "api.yaml", "", "", new OpenApiImportOptions(
            OpenApiImportOptions.ParameterPolicy.REQUIRED_VARIABLES,
            java.util.Map.of("tenantId", "live", "required", "shared"))).get(0);
        assertTrue(required.url().endsWith("?required=shared&limit=10"));
    }

    @Test
    void allVariableModeRequiresValuesEvenWhenTheSpecProvidesDefaults() {
        var error = org.junit.jupiter.api.Assertions.assertThrows(
            OpenApiImportOptions.MissingVariablesException.class,
            () -> new OpenApiSpecParser().parse(VARIABLE_SPEC, "api.yaml", "", "",
                new OpenApiImportOptions(OpenApiImportOptions.ParameterPolicy.ALL_VARIABLES, java.util.Map.of())));
        assertTrue(error.getMessage().contains("tenantId"));
        assertTrue(error.getMessage().contains("tenant"));
        assertTrue(error.getMessage().contains("limit"));
        assertTrue(error.getMessage().contains("optional"));
    }

    @Test
    void resolvesBodyTemplatesBeforeJsonAndFormSerialization() {
        String spec = """
            openapi: 3.0.3
            servers: [{url: https://api.example.test}]
            paths:
              /json:
                post:
                  requestBody:
                    content:
                      application/json:
                        example: {tenantId: '{{tenantId}}', nested: ['{tenantId}']}
              /form:
                post:
                  requestBody:
                    content:
                      application/x-www-form-urlencoded:
                        example: {tenantId: '{{tenantId}}'}
            """;
        var operations = new OpenApiSpecParser().parse(spec, "api.yaml", "", "",
            new OpenApiImportOptions(null, java.util.Map.of("tenantId", "acme\"& /")));
        var json = com.google.gson.JsonParser.parseString(operations.get(0).body()).getAsJsonObject();
        assertEquals("acme\"& /", json.get("tenantId").getAsString());
        assertEquals("acme\"& /", json.getAsJsonArray("nested").get(0).getAsString());
        assertEquals("tenantId=acme%22%26+%2F", operations.get(1).body());
    }

    @Test
    void missingAndCyclicVariablesFailWithoutSubstitutingASample() {
        String spec = VARIABLE_SPEC;
        for (var variables : java.util.List.of(java.util.Map.<String, String>of(),
            java.util.Map.of("tenantId", ""), java.util.Map.of("tenantId", "{{other}}", "other", "{{tenantId}}"))) {
            var error = org.junit.jupiter.api.Assertions.assertThrows(
                OpenApiImportOptions.MissingVariablesException.class,
                () -> new OpenApiSpecParser().parse(spec, "api.yaml", "", "",
                    new OpenApiImportOptions(OpenApiImportOptions.ParameterPolicy.REQUIRED_VARIABLES, variables)));
            assertTrue(error.getMessage().contains("tenantId"));
        }
    }

    @Test
    void templateParsingRetainsOperationsAndReadablePlaceholdersForEveryParameterMode() {
        var parser = new OpenApiSpecParser();
        for (var policy : OpenApiImportOptions.ParameterPolicy.values()) {
            var operations = parser.parseTemplates(VARIABLE_SPEC, "api.yaml", "", "",
                new OpenApiImportOptions(policy, java.util.Map.of()));
            assertEquals(2, operations.size(), policy.toString());
            assertEquals(policy == OpenApiImportOptions.ParameterPolicy.ALL_VARIABLES
                ? "{{X-Tenant}}" : "{{tenantId}}", operations.get(0).headers().get("X-Tenant"));
            assertTrue(operations.get(0).unresolvedVariables().contains("tenantId"));
            assertTrue(operations.get(1).unresolvedVariables().isEmpty()
                || policy == OpenApiImportOptions.ParameterPolicy.ALL_VARIABLES);
            assertEquals(operations.get(0).source().path(), "/tenants/{tenantId}/items");
        }
        var templates = parser.parseTemplates(VARIABLE_SPEC, "api.yaml", "", "",
            new OpenApiImportOptions(OpenApiImportOptions.ParameterPolicy.ALL_VARIABLES, java.util.Map.of()));
        assertEquals("https://{{tenant}}.example.test/api/tenants/{{tenantId}}/items"
            + "?required={{required}}&optional={{optional}}&limit={{limit}}", templates.get(0).url());
        assertEquals("/api/tenants/{{tenantId}}/items?required={{required}}&optional={{optional}}&limit={{limit}}",
            templates.get(0).requestTarget());
        assertEquals("{{tenant}}.example.test", templates.get(0).authority());
    }

    @Test
    void relativeServerTemplatesResolveAgainstTheDocumentUrlWithoutLosingVariables() {
        String spec = """
            openapi: 3.0.3
            servers: [{url: '/{tenantId}/api', variables: {tenantId: {default: sample}}}]
            paths: {/health: {get: {responses: {}}}}
            """;
        var operations = new OpenApiSpecParser().parseTemplates(spec, "api.yaml", "",
            "https://api.example.test/docs/openapi.yaml", new OpenApiImportOptions(
                OpenApiImportOptions.ParameterPolicy.ALL_VARIABLES, java.util.Map.of()));
        assertEquals("https://api.example.test/{{tenantId}}/api/health", operations.get(0).url());
        assertEquals(java.util.Set.of("tenantId"), operations.get(0).unresolvedVariables());
    }

    @Test
    void discoversAllRequestVariablesAndPrefersSpecValuesOverGeneratedSamples() {
        String spec = """
            openapi: 3.0.3
            servers: [{url: 'https://{tenantHost}.example.test', variables: {tenantHost: {default: demo}}}]
            components:
              parameters:
                Region: {name: region, in: query, schema: {type: string, default: US}}
            paths:
              /tenants/{tenantId}/items:
                get:
                  parameters:
                    - {name: tenantId, in: path, required: true, example: example-tenant}
                    - {$ref: '#/components/parameters/Region'}
                    - {name: limit, in: query, schema: {type: integer}}
                    - {name: X-Tenant, in: header, example: '{{tenantId}}'}
                    - {name: session, in: cookie, schema: {type: string, default: cookie-example}}
                  requestBody:
                    content:
                      application/json:
                        example: {token: '{{bodyToken}}'}
                  responses:
                    '200': {description: '{{responseOnly}}'}
              /tenants/{tenantId}/reports:
                get:
                  parameters:
                    - {name: tenantId, in: path, schema: {type: string}}
            """;
        var samples = new OpenApiSpecParser().variableSamples(spec, "api.yaml");
        assertEquals(java.util.Set.of("tenantHost", "tenantId", "region", "limit", "X-Tenant", "session", "bodyToken"),
            samples.keySet());
        assertEquals("example-tenant", samples.get("tenantId"));
        assertEquals("demo", samples.get("tenantHost"));
        assertEquals("US", samples.get("region"));
        assertEquals("1", samples.get("limit"));
        assertEquals("{{tenantId}}", samples.get("X-Tenant"));
        assertEquals("bodyToken", samples.get("bodyToken"));
        assertEquals("cookie-example", samples.get("session"));
    }

    @Test
    void conflictingExamplesStayBlankAndSelfReferencesGetAGeneratedValue() {
        String spec = """
            openapi: 3.0.3
            paths:
              /first/{id}:
                get:
                  parameters:
                    - {name: id, in: path, example: first}
                    - {name: tenantId, in: query, example: '{{tenantId}}'}
              /second/{id}:
                get:
                  parameters: [{name: id, in: path, example: second}]
            """;
        var samples = new OpenApiSpecParser().variableSamples(spec, "api.yaml");
        assertEquals("", samples.get("id"));
        assertEquals("tenantId", samples.get("tenantId"));
    }

    @Test
    void filledStructuredSamplesRetainTheirDeclaredQuerySerialization() {
        String spec = """
            openapi: 3.0.3
            servers: [{url: https://api.example.test}]
            paths:
              /search:
                get:
                  parameters:
                    - name: ids
                      in: query
                      schema: {type: array, default: [1, 2]}
                    - name: filter
                      in: query
                      style: deepObject
                      schema: {type: object, default: {active: true}}
            """;
        var parser = new OpenApiSpecParser();
        var unresolved = parser.parseTemplates(spec, "api.yaml", "", "", new OpenApiImportOptions(
            OpenApiImportOptions.ParameterPolicy.ALL_VARIABLES, java.util.Map.of()));
        assertEquals(java.util.Set.of("ids", "filter"), unresolved.get(0).unresolvedVariables());
        var operation = parser.parse(spec, "api.yaml", "", "", new OpenApiImportOptions(
            OpenApiImportOptions.ParameterPolicy.ALL_VARIABLES, parser.variableSamples(spec, "api.yaml"))).get(0);
        assertEquals("https://api.example.test/search?ids=1&ids=2&filter%5Bactive%5D=true", operation.url());
    }

    @Test
    void nullSchemaExamplesAndDefaultsStillGenerateSamplesForTheDeclaredFormat() {
        String spec = """
            openapi: 3.0.1
            servers: [{url: https://api.example.test}]
            paths:
              /items/{mediaItemKey}/restore:
                patch:
                  parameters:
                    - name: mediaItemKey
                      in: path
                      required: true
                      schema: {type: string, format: uuid, example: null, default: null}
                  responses: {'200': {description: OK}}
              /items:
                post:
                  requestBody:
                    content:
                      application/json:
                        schema:
                          type: object
                          properties:
                            id: {type: string, format: uuid, default: null}
                            enabled: {type: boolean, example: null, default: false}
                            count: {type: integer, example: null, default: 0}
                            category: {type: string, example: null, default: null, enum: [first, second]}
            """;
        var parser = new OpenApiSpecParser();
        var samples = parser.variableSamples(spec, "api.yaml");
        assertEquals("00000000-0000-4000-8000-000000000000", samples.get("mediaItemKey"));
        java.util.UUID.fromString(samples.get("mediaItemKey"));
        var operations = parser.parse(spec, "api.yaml");
        var patch = operations.stream().filter(op -> op.method().equals("PATCH")).findFirst().orElseThrow();
        assertEquals("https://api.example.test/items/00000000-0000-4000-8000-000000000000/restore", patch.url());
        assertEquals("", patch.body());
        assertTrue(patch.headers().isEmpty());
        var post = operations.stream().filter(op -> op.method().equals("POST")).findFirst().orElseThrow();
        var body = com.google.gson.JsonParser.parseString(post.body()).getAsJsonObject();
        assertEquals("00000000-0000-4000-8000-000000000000", body.get("id").getAsString());
        assertEquals(false, body.get("enabled").getAsBoolean());
        assertEquals(0, body.get("count").getAsInt());
        assertEquals("first", body.get("category").getAsString());
    }

    @Test
    void queryOnlyPutKeepsDeclaredLocationsAndDoesNotInventABody() {
        String spec = """
            openapi: 3.0.1
            servers: [{url: https://api.example.test}]
            components:
              schemas:
                PrintOptions: {type: string, enum: [undefined, yes, onFirstFillOnly, no]}
            paths:
              /items/{mediaItemKey}:
                put:
                  parameters:
                    - {name: mediaItemKey, in: path, required: true, schema: {type: string, format: uuid, default: null}}
                    - {name: tenant.id, in: query, required: true, schema: {type: integer}}
                    - {name: 'ws:prod.id', in: query, schema: {type: string}}
                    - {name: FileName, in: query, required: true, schema: {type: string}}
                    - {name: IsPrintWithDeliveryTicketOption, in: query, schema: {$ref: '#/components/schemas/PrintOptions'}}
                    - {name: StoreFile, in: query, schema: {type: boolean}}
            """;
        var parser = new OpenApiSpecParser();
        var values = new java.util.LinkedHashMap<>(parser.variableSamples(spec, "api.yaml"));
        values.put("tenant.id", "1105");
        values.put("mediaItemKey", "11111111-2222-4333-8444-555555555555");
        var operation = parser.parse(spec, "api.yaml", "", "", new OpenApiImportOptions(
            OpenApiImportOptions.ParameterPolicy.ALL_VARIABLES, values)).get(0);
        assertEquals("PUT", operation.method());
        assertTrue(operation.url().contains("/items/11111111-2222-4333-8444-555555555555?tenant.id=1105"));
        assertTrue(operation.url().contains("ws%3Aprod.id=ws%3Aprod.id"));
        assertTrue(operation.url().contains("IsPrintWithDeliveryTicketOption=undefined"));
        assertTrue(operation.url().endsWith("StoreFile=true"));
        assertEquals("", operation.body());
        assertTrue(operation.headers().isEmpty());
    }

}

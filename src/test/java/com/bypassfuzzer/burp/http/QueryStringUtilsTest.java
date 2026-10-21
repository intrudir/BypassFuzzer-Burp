package com.bypassfuzzer.burp.http;
import com.bypassfuzzer.core.http.QueryStringUtils;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class QueryStringUtilsTest {

    @Test
    void parsesAndDecodesPathQuery() {
        Map<String, String> params = QueryStringUtils.parsePathQueryDecoded("/admin?debug=true&name=John%20Doe&empty");

        assertEquals(Map.of("debug", "true", "name", "John Doe", "empty", ""), params);
    }

    @Test
    void replacesParameterValuePreservingOrder() {
        String updated = QueryStringUtils.replaceValue("/admin?debug=true&role=user", "role", "admin");

        assertEquals("/admin?debug=true&role=admin", updated);
    }

    @Test
    void renamesParameterPreservingQueryOrder() {
        String updated = QueryStringUtils.replaceName("/admin?debug=true&role=user", "debug", "trace");

        assertEquals("/admin?trace=true&role=user", updated);
    }

    @Test
    void buildsQueryStringFromOrderedMap() {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("first", "1");
        params.put("second", "2");

        assertEquals("first=1&second=2", QueryStringUtils.toQueryString(params));
    }

    @Test
    void upsertsParameterByReplacingExistingName() {
        String updated = QueryStringUtils.upsertParameter("/admin?debug=false&role=user", "debug=true");

        assertEquals("/admin?debug=true&role=user", updated);
    }

    @Test
    void upsertsParameterByAppendingWhenNameDoesNotExist() {
        String updated = QueryStringUtils.upsertParameter("/admin?role=user", "debug=true");

        assertEquals("/admin?role=user&debug=true", updated);
    }

    @Test
    void replacesDuplicateParameterValuesWithoutCollapsingThem() {
        String updated = QueryStringUtils.replaceValue("/admin?debug=1&debug=2&role=user", "debug", "true");

        assertEquals("/admin?debug=true&debug=true&role=user", updated);
    }

    @Test
    void upsertsParameterWithoutDiscardingDuplicateNames() {
        String updated = QueryStringUtils.upsertParameter("/admin?debug=1&debug=2&role=user", "debug=true");

        assertEquals("/admin?debug=true&debug=true&role=user", updated);
    }
}

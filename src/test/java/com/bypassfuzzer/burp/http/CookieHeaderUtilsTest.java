package com.bypassfuzzer.burp.http;
import com.bypassfuzzer.core.http.CookieHeaderUtils;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CookieHeaderUtilsTest {

    @Test
    void parsesCookieHeaderPreservingOrder() {
        Map<String, String> cookies = CookieHeaderUtils.parse("session=abc; debug=true; theme=light");

        assertEquals("abc", cookies.get("session"));
        assertEquals("true", cookies.get("debug"));
        assertEquals("light", cookies.get("theme"));
    }

    @Test
    void replacesCookieValueWithoutDroppingOthers() {
        String updated = CookieHeaderUtils.replaceValue("session=abc; debug=true; theme=light", "debug", "false");

        assertEquals("session=abc; debug=false; theme=light", updated);
    }

    @Test
    void appendsCookieToExistingHeader() {
        assertEquals("session=abc; debug=true", CookieHeaderUtils.appendCookie("session=abc", "debug=true"));
        assertEquals("debug=true", CookieHeaderUtils.appendCookie("", "debug=true"));
    }

    @Test
    void upsertsCookieByReplacingExistingName() {
        assertEquals(
            "session=abc; debug=false; theme=light",
            CookieHeaderUtils.upsertCookie("session=abc; debug=true; theme=light", "debug=false")
        );
    }

    @Test
    void upsertsCookieByAppendingWhenNameDoesNotExist() {
        assertEquals(
            "session=abc; debug=true",
            CookieHeaderUtils.upsertCookie("session=abc", "debug=true")
        );
    }

    @Test
    void replacesDuplicateCookieValuesWithoutCollapsingThem() {
        String updated = CookieHeaderUtils.replaceValue("session=abc; debug=1; debug=2; theme=light", "debug", "true");

        assertEquals("session=abc; debug=true; debug=true; theme=light", updated);
    }

    @Test
    void upsertsCookieWithoutDiscardingDuplicateNames() {
        String updated = CookieHeaderUtils.upsertCookie("session=abc; debug=1; debug=2; theme=light", "debug=true");

        assertEquals("session=abc; debug=true; debug=true; theme=light", updated);
    }
}

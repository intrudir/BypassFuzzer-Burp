package com.bypassfuzzer.burp.session;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.attacks.AttackType;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class SessionPreflightAnalyzer {

    public List<String> analyze(HttpRequest request, SessionRunOptions runOptions) {
        List<String> warnings = new ArrayList<>();
        Set<AttackType> enabledAttackTypes = runOptions.enabledAttackTypes();

        if (isRootPath(request)) {
            List<String> skippedAttacks = new ArrayList<>();
            if (enabledAttackTypes.contains(AttackType.PATH)) {
                skippedAttacks.add("Path");
            }
            if (enabledAttackTypes.contains(AttackType.TRAILING_SLASH)) {
                skippedAttacks.add("Trailing Slash");
            }
            if (enabledAttackTypes.contains(AttackType.EXTENSION)) {
                skippedAttacks.add("Extension");
            }
            if (enabledAttackTypes.contains(AttackType.ENCODING)) {
                skippedAttacks.add("Encoding");
            }

            if (!skippedAttacks.isEmpty()) {
                warnings.add(String.join(", ", skippedAttacks)
                    + " attack" + (skippedAttacks.size() > 1 ? "s" : "")
                    + " will be skipped (root path '/' detected)");
            }
        }

        return warnings;
    }

    private boolean isRootPath(HttpRequest request) {
        String path = request.pathWithoutQuery();
        return path == null || path.isEmpty() || "/".equals(path);
    }

}

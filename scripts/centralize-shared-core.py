#!/usr/bin/env python3
"""Idempotently migrate the Burp master's transport-independent types into core."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = {
    **{f"com.bypassfuzzer.burp.core.coverage.{name}": f"com.bypassfuzzer.core.input.{name}"
       for name in ("OpenApiOperation", "OpenApiSpecParser", "PostmanCollectionParser")},
    **{f"com.bypassfuzzer.burp.core.payloads.{name}": f"com.bypassfuzzer.core.payloads.{name}"
       for name in ("PayloadLoader", "PayloadRepository", "StandalonePathMarkerVariants", "UrlPayloadProcessor")},
    **{f"com.bypassfuzzer.burp.core.urlvalidation.{name}": f"com.bypassfuzzer.core.urlvalidation.{name}"
       for name in ("UnicodeCompatibilityVariants", "UrlValidationAttackSetting", "UrlValidationContext",
                    "UrlValidationEncoding", "UrlValidationPayload")},
    **{f"com.bypassfuzzer.burp.http.{name}": f"com.bypassfuzzer.core.http.{name}"
       for name in ("ConfiguredHeader", "ConfiguredHeaderParser", "UserAgentMode", "CookieHeaderUtils",
                    "LocatedParameter", "ParameterLocation", "RequestBodyFormat", "QueryStringUtils", "RequestPathUtils")},
    **{f"com.bypassfuzzer.burp.core.throttle.{name}": f"com.bypassfuzzer.core.throttle.{name}"
       for name in ("ThrottleSettings", "AdaptiveRateController")},
}


def main():
    for old, new in MIGRATIONS.items():
        source = ROOT / "src/main/java" / (old.replace(".", "/") + ".java")
        destination = ROOT / "core/src/main/java" / (new.replace(".", "/") + ".java")
        if source.exists():
            if not destination.exists():
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(source.read_text().replace(old.rsplit(".", 1)[0], new.rsplit(".", 1)[0]))
            source.unlink()
    roots = [ROOT / area for area in ("src", "core/src", "cli/src", "scripts")]
    for directory in roots:
        for path in directory.rglob("*.java"):
            text = path.read_text()
            original = text
            for old, new in MIGRATIONS.items():
                text = re.sub(re.escape(old) + r"\b", new, text)
                name = new.rsplit(".", 1)[1]
                package = re.search(r"^package ([\w.]+);", text, re.M)
                own_package = package.group(1) if package else ""
                if re.search(r"\b" + name + r"\b", text) and own_package != new.rsplit(".", 1)[0]:
                    if f"import {new};" not in text and not re.search(r"(?:class|enum|record) " + name + r"\b", text):
                        text = text.replace(package.group(0), package.group(0) + f"\nimport {new};", 1)
            if text != original:
                path.write_text(text)


if __name__ == "__main__":
    main()

# BypassFuzzer - Burp Suite Extension

A Burp Suite extension for testing authorization bypass vulnerabilities (401/403 bypasses). This is a Java port of the Python [BypassFuzzer](https://github.com/intrudir/BypassFuzzer) tool, fully integrated with Burp Suite.

## Features

- **8 Attack Types:**
  - Header-based attacks (283+ bypass headers)
  - Path manipulation (367+ URL encodings)
  - HTTP verb/method attacks (11 methods + overrides)
  - Debug parameter injection (31 common debug params with case variations)
  - Trailing dot attack (absolute domain notation)
  - Trailing slash attack (tests with/without trailing slash)
  - HTTP protocol attacks (e.g. HTTP/1.0, HTTP/0.9)
  - Case variation attack (random capitalizations with smart limits)

- **Smart Filtering:** Automatically reduces noise by hiding repeated responses with pattern tracking
- **Custom Payloads:** Load your own payload files if needed
- **Collaborator Integration:** Optional Burp Collaborator payloads for header attacks (Burp Professional only)
- **Burp Integration:**
  - Right-click menu: "Send to BypassFuzzer"
  - Send results to Repeater/Intruder
  - Graceful shutdown and resource cleanup
- Colorize interesting requests for future filtering

## Requirements

- Java 17 or higher
- Burp Suite Professional or Community Edition (2023.10+)
- Gradle 7.0+ (for building)

## Building

```bash
# Navigate to the extension directory
cd burp-extension

# Build the extension JAR
./gradlew clean shadowJar

# The compiled JAR will be at:
# build/libs/bypassfuzzer-burp-1.0.0.jar
```

## Installation

1. Open Burp Suite
2. Go to **Extensions** → **Installed**
3. Click **Add**
4. Select **Extension file**: `bypassfuzzer-burp-1.0.0.jar`
5. Click **Next**
6. The extension will load and a "BypassFuzzer" tab will appear

## Usage

### Basic Workflow

1. **Send Request to BypassFuzzer:**
   - Right-click any request in Proxy, Target, or Repeater
   - Select "Send to BypassFuzzer"

2. **Configure Attack:**
   - Select attack types to enable (or use Check All/Uncheck All)
   - Optionally enable Collaborator payloads (Burp Professional only)
   - Optionally load custom payloads

3. **Start Fuzzing:**
   - Click "Start Fuzzing"
   - Results appear in real-time, filtered with your criteria in real-time
   - Can stop fuzzing at any time with "Stop Fuzzing" button
   - Can right click a request to color it for identification/filtering later

4. **Review Results:**
   - Dynamic filtering based on status codes, length, content-type, etc.
   - Use smart filter to see only interesting results automatically
   - Click any result to view full request/response
   - Send interesting findings to Repeater or Intruder

5. **Scan History:**
   - Export results to CSV/JSON (TODO)

## Custom Payloads

You can provide your own payload files:

1. **Header Templates:** One template per line, use placeholders:
   - `{IP PAYLOAD}` - Replaced with IP addresses from ip_payloads.txt
   - `{URL PAYLOAD}` - Replaced with full target URL
   - `{PATH PAYLOAD}` - Replaced with URL path only
   - `{OOB PAYLOAD}` - Replaced with OOB server URL (if configured)
   - `{OOB DOMAIN PAYLOAD}` - Replaced with OOB domain only
   - `{WHITESPACE PAYLOAD}` - Replaced with whitespace character

   Example: `X-Forwarded-For: {IP PAYLOAD}`

2. **IP Payloads:** One IP address per line

   Example: `127.0.0.1`

3. **URL Payloads:** One URL encoding/pattern per line

   Example: `/../`

4. **Parameter Payloads:** One parameter=value per line

   Example: `debug=true`

## Credits

- Original Python tool: [@intrudir](https://twitter.com/intrudir)
- Smart filter algorithm: [@defparam](https://twitter.com/defparam)

## License
TODO

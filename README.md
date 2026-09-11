# Interactsh Bridge 1.0.0

A standalone **Burp Suite extension for Interactsh**, adapted from the customized Collab client in Arken Proxy. Connect to a public or self-hosted Interactsh server, generate callback addresses, and inspect the interactions returned to your session.

This is an independent integration, not an official ProjectDiscovery or PortSwigger release. It communicates directly with Interactsh-compatible servers; Arken Proxy, its Python backend, Electron, and Docker are not required to run the extension.

## Install

1. In Burp, open **Extensions → Installed → Add**.
2. Select **Java** and load `build/Interactsh-Bridge.jar` (or the separately supplied versioned JAR).
3. Open **Interactsh Bridge → Connection**.
4. Choose **Public Interactsh** and one of the listed servers, or **Custom server** and your server's URL/authentication token.
5. Keep correlation-ID length **20** and nonce length **13** unless your custom server uses different values. These lengths must match the server.
6. Click **Connect**. The extension generates a key pair, registers the session, and confirms a successful poll before showing it as connected.
7. Use **New address** and **Copy address** in the Interactions tab. Callbacks received by the configured server appear as polling results.

An Interactsh server is required. This extension does not host the DNS/HTTP/mail services itself. Public server availability and protocol support depend on the selected server. No public server is contacted until you explicitly connect.

## Features

- Public server presets and custom server origins with optional authentication.
- RSA-2048 session keys; current upstream AES-CTR interaction decoding, plus legacy CFB/OFB compatibility retained from Arken.
- Automatic polling, manual polling, disconnect, and unload cleanup.
- Callback address generation and clipboard copying.
- Search and protocol filters across DNS, HTTP/HTTPS, SMTP/SMTPS, LDAP, FTP, SMB, and other reported protocols.
- Sortable interaction table with request, response, details, and raw JSON panes.
- Workspace notes and JSON interaction export.
- Password-protected session save/resume, separate from interaction exports.
- Verified HTTPS connections, bounded responses and interaction retention, and visible polling errors.
- Native Swing UI that uses Burp's theme.

This is a callback client and interaction viewer. It does not automatically edit/replay requests, scan targets, generate exploit templates, or run external tools. Copying a callback address does not send any traffic to a target.

## Sessions and server changes

To change servers, click **Disconnect**, open Connection, change the server, and connect again. Every fresh connection creates a new session. A failed connection does not silently reuse an old server's correlation ID. Captured rows remain visible with their source-server and session metadata.

**Disconnect** stops local polling and attempts deregistration. Deregistration is best effort; a server that is unreachable may retain the session until it expires. Unloading the extension stops polling without deregistering, allowing an explicitly saved session to be resumed later.

**Save session…** stores the server URL, token, IDs, and RSA key pair in a password-protected `.ibs` file. The format uses PBKDF2-HMAC-SHA256 (210,000 iterations) and AES-256-GCM. Use a password of at least 12 characters. This is Interactsh Bridge's own session format, not the upstream CLI's YAML format.

**Resume session…** restores the encrypted session and verifies that it can poll. A still-active server registration may reject a duplicate registration; polling must still succeed before the UI calls the session connected. An expired registration can be re-created, but callbacks already removed by the server cannot be recovered.

Non-secret connection preferences are saved in Burp's preferences. Tokens and private keys are not automatically saved. Session backups contain credentials; ordinary interaction exports do not include the client's token, private key, or polling secret. Captured interaction content may itself contain sensitive information.

Interaction history and notes remain in memory until explicitly exported. They are not restored from an `.ibs` session backup. Group renaming and the original browser theme picker are not included; interactions can be sorted by server or identifier, and Burp supplies the theme.

## Connection behavior and limits

- Poll interval: 1–300 seconds, default 5, measured as a fixed delay after each scheduled poll finishes.
- Network timeout: 1–120 seconds, default 30. Connection establishment is capped at 10 seconds.
- One network worker per extension; polls do not overlap. Late results from a disconnected session are discarded.
- HTTP redirects and system HTTP proxies are not followed. There is no automatic downgrade from HTTPS to HTTP.
- Standard Java TLS trust validation is enabled. For private CAs, configure Burp's Java runtime trust store. No certificate-verification bypass is provided.
- Custom URL must be a server origin, without a path/query. A port is allowed. Callback addresses use the server hostname, not the API port.
- Maximum polling response: 4 MiB. Retention: 5,000 records or approximately 32 MiB of serialized interaction data, whichever is reached first. Oldest records are evicted; the UI shows the eviction count. Java object overhead is additional.
- Poll failures are shown in the status area and polling continues at the configured interval. Reconnect if the session has expired or authentication changes.

## Build

Requirements: JDK 17+, Bash, curl, Python 3. Internet access is needed for the first dependency download.

```sh
./build.sh
```

The build downloads pinned Montoya API 2026.7 and Gson 2.14.0 artifacts from Maven Central, verifies SHA-256 checksums, compiles Java 17 bytecode, runs the test harness, and creates `build/Interactsh-Bridge.jar`. Burp provides Montoya at runtime; only Gson is bundled. Use a recent Burp version supporting Montoya 2026.7.

Sources:

- `BridgeExtension.java`: Montoya entry point.
- `BridgePanel.java`: configuration, results UI, and exports.
- `InteractshClient.java`: protocol, HTTP transport, and cryptography.
- `SessionController.java`: registration and serialized polling lifecycle.
- `SessionFile.java`: protected session files.
- `InteractionStore.java`: bounded records and deduplication.

All Java sources are under `src/main/java/interactshbridge/`. Tests are under `src/test/java/interactshbridge/`.

## Verification

The test harness uses a loopback mock Interactsh server and synthetic interactions. It covers cryptographic modes, session file protection, registration/authentication, active and expired session resume, malformed records, redirects, deregistration, serial polling, stale-event suppression, retention, filtering, detail rendering, and Montoya tab registration. It also renders native UI previews under `work/`.

**Build result: 37 automated checks passed.** The Interactions and Connection layouts were visually inspected using synthetic data.

The delivered JAR has not been loaded into a live Burp session or connected to a live public/custom Interactsh server during this build. The remaining runtime acceptance check is loading it into Burp and verifying a benign callback against your chosen server.

## Provenance

Adapted from the user's Arken Proxy Collab implementation:

- `src/pages/Collab.jsx`
- `public/interactsh/index.html`
- `backend/api/routers/tools_router.py`

Protocol references:

- [ProjectDiscovery Interactsh client](https://github.com/projectdiscovery/interactsh/blob/main/pkg/client/client.go)
- [Interactsh defaults](https://github.com/projectdiscovery/interactsh/blob/main/pkg/settings/default.go)
- [PortSwigger Montoya API](https://github.com/PortSwigger/burp-extensions-montoya-api)

No upstream Go implementation is bundled. Gson's Apache 2.0 license and attribution are included in `src/main/resources/META-INF/` and the JAR. No new license is asserted for the user's Arken-derived code.

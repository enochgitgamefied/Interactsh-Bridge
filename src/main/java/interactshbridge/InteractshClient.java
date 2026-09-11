package interactshbridge;

import com.google.gson.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.util.concurrent.CancellationException;
import javax.crypto.*;
import javax.crypto.spec.*;

/** Interactsh wire protocol; adapted from Arken Collab and checked against ProjectDiscovery's client. */
final class InteractshClient implements AutoCloseable {
    static final Gson JSON = new GsonBuilder().setPrettyPrinting().create();
    static final List<String> PUBLIC = List.of("https://oast.fun", "https://oast.pro", "https://oast.live", "https://oast.site", "https://oast.online", "https://oast.me");
    static final SecureRandom RANDOM = new SecureRandom();
    static final String ALPHABET = "ybndrfg8ejkmcpqxot1uwisza345h769";
    record Config(String url, String token, int idLength, int nonceLength, int interval, int timeout) {
        Config {
            url = url.trim().replaceAll("/+$", "");
            URI parsed = URI.create(url);
            if (!Set.of("https", "http").contains(Objects.toString(parsed.getScheme(), "")) || parsed.getHost() == null
                || parsed.getUserInfo() != null || parsed.getQuery() != null || parsed.getFragment() != null || !parsed.getPath().isEmpty())
                throw new IllegalArgumentException("Use a server origin such as https://oast.fun, without a path, query, or credentials.");
            if (idLength < 3 || nonceLength < 3 || idLength + nonceLength > 63)
                throw new IllegalArgumentException("ID and nonce must each be at least 3 characters and total at most 63. They must match your server configuration.");
            if (interval < 1 || interval > 300 || timeout < 1 || timeout > 120)
                throw new IllegalArgumentException("Polling interval: 1–300 seconds. Network timeout: 1–120 seconds.");
            if (token == null || token.indexOf('\n') >= 0 || token.indexOf('\r') >= 0) throw new IllegalArgumentException("Invalid authentication token.");
        }
    }
    record Session(Config config, String id, String secret, KeyPair keys) {
        String address() { return id + random(config.nonceLength()) + "." + URI.create(config.url()).getHost(); }
    }
    record Poll(List<JsonObject> interactions, int rejected) {}
    static final class HttpFailure extends IOException {
        final int status;
        HttpFailure(int status) { super("Server returned HTTP " + status + (status == 401 || status == 403 ? ". Check the authentication token." : ". Check server logs and session status.")); this.status = status; }
    }
    final Session session;
    private volatile HttpURLConnection active;
    private volatile boolean closed;
    InteractshClient(Session session) { this.session = session; }
    static Session create(Config config) throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048);
        return new Session(config, random(config.idLength()), random(40), generator.generateKeyPair());
    }
    static String random(int length) {
        StringBuilder b = new StringBuilder(length);
        for (int i = 0; i < length; i++) b.append(ALPHABET.charAt(RANDOM.nextInt(32)));
        return b.toString();
    }
    void check() { if (closed || Thread.currentThread().isInterrupted()) throw new CancellationException("Request cancelled"); }
    @Override public void close() { closed = true; HttpURLConnection c = active; if (c != null) c.disconnect(); }
    JsonObject request(String path, JsonObject body) throws IOException {
        check(); HttpURLConnection c = (HttpURLConnection) URI.create(session.config.url() + path).toURL().openConnection(Proxy.NO_PROXY);
        active = c;
        try {
            check(); c.setConnectTimeout(Math.min(10000, session.config.timeout() * 1000)); c.setReadTimeout(session.config.timeout() * 1000);
            c.setInstanceFollowRedirects(false); c.setRequestProperty("Accept", "application/json");
            if (!session.config.token().isBlank()) c.setRequestProperty("Authorization", session.config.token());
            if (body != null) {
                c.setRequestMethod("POST"); c.setDoOutput(true); c.setRequestProperty("Content-Type", "application/json");
                byte[] bytes = body.toString().getBytes(StandardCharsets.UTF_8); c.setFixedLengthStreamingMode(bytes.length);
                try (OutputStream out = c.getOutputStream()) { out.write(bytes); }
            }
            int status = c.getResponseCode(); check(); if (status != 200) throw new HttpFailure(status);
            try (InputStream in = c.getInputStream()) {
                byte[] bytes = in.readNBytes(4 * 1024 * 1024 + 1); check();
                if (bytes.length > 4 * 1024 * 1024) throw new IOException("Server response exceeds 4 MiB.");
                JsonObject result = JsonParser.parseString(new String(bytes, StandardCharsets.UTF_8)).getAsJsonObject();
                if (result.has("error") && !result.get("error").isJsonNull() && !result.get("error").getAsString().isBlank()) throw new IOException("Server reported a session error. Check its logs or reconnect.");
                return result;
            }
        } catch (SocketTimeoutException e) { check(); throw new IOException("Server timeout. Adjust Network timeout or check the server connection.", e); }
        catch (JsonParseException | IllegalStateException e) { throw new IOException("Server returned invalid JSON.", e); }
        finally { c.disconnect(); active = null; }
    }
    void register() throws IOException {
        JsonObject data = credentials();
        String pem = "-----BEGIN RSA PUBLIC KEY-----\n" + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(session.keys.getPublic().getEncoded()) + "\n-----END RSA PUBLIC KEY-----\n";
        data.addProperty("public-key", Base64.getEncoder().encodeToString(pem.getBytes(StandardCharsets.US_ASCII)));
        JsonObject reply = request("/register", data);
        if (!text(reply, "message").equals("registration successful")) throw new IOException("Server did not confirm registration.");
    }
    private JsonObject credentials() { JsonObject data = new JsonObject(); data.addProperty("correlation-id", session.id); data.addProperty("secret-key", session.secret); return data; }
    void deregister() throws IOException { request("/deregister", credentials()); }
    Poll resume() throws IOException {
        // A live session may reject duplicate registration. Confirm it by actually polling.
        try { register(); } catch (IOException registration) {
            try { return poll(); } catch (IOException polling) { polling.addSuppressed(registration); throw polling; }
        }
        return poll();
    }
    Poll poll() throws IOException {
        JsonObject reply = request("/poll?id=" + URLEncoder.encode(session.id, StandardCharsets.UTF_8) + "&secret=" + URLEncoder.encode(session.secret, StandardCharsets.UTF_8), null);
        List<JsonObject> entries = new ArrayList<>(); int rejected = 0;
        try {
            JsonArray data = array(reply, "data");
            if (data.size() > 0) {
                byte[] key;
                try {
                    Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
                    rsa.init(Cipher.DECRYPT_MODE, session.keys.getPrivate(), new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
                    key = rsa.doFinal(Base64.getDecoder().decode(text(reply, "aes_key")));
                } catch (GeneralSecurityException | IllegalArgumentException ex) { throw new IOException("Unable to decrypt the interaction key for this session.", ex); }
                for (JsonElement item : data) {
                    try { entries.add(decrypt(key, item.getAsString())); }
                    catch (GeneralSecurityException | RuntimeException ex) { rejected++; }
                }
                Arrays.fill(key, (byte) 0);
            }
            for (String field : List.of("extra", "tlddata")) for (JsonElement item : array(reply, field)) {
                try { entries.add(JsonParser.parseString(item.getAsString()).getAsJsonObject()); } catch (RuntimeException ex) { rejected++; }
            }
            return new Poll(entries, rejected);
        } catch (IllegalStateException ex) { throw new IOException("Unexpected polling response format.", ex); }
    }
    private static JsonArray array(JsonObject reply, String field) { return !reply.has(field) || reply.get(field).isJsonNull() ? new JsonArray() : reply.getAsJsonArray(field); }
    static JsonObject decrypt(byte[] key, String encoded) throws GeneralSecurityException {
        byte[] raw = Base64.getDecoder().decode(encoded);
        if (raw.length <= 16) throw new IllegalArgumentException("Short encrypted interaction");
        // Current upstream uses CTR. CFB/OFB support preserves Arken's older custom-server compatibility.
        for (String mode : List.of("CTR", "CFB", "OFB")) {
            try {
                Cipher aes = Cipher.getInstance("AES/" + mode + "/NoPadding"); aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(raw, 0, 16));
                JsonObject object = JsonParser.parseString(new String(aes.doFinal(raw, 16, raw.length - 16), StandardCharsets.UTF_8)).getAsJsonObject();
                if (!object.has("protocol")) continue;
                return object;
            } catch (RuntimeException ex) { /* try compatibility mode */ }
        }
        throw new IllegalArgumentException("Unable to decode encrypted interaction");
    }
    static String text(JsonObject object, String field) { JsonElement value = object.get(field); return value == null || value.isJsonNull() ? "" : value.isJsonPrimitive() ? value.getAsString() : value.toString(); }
}

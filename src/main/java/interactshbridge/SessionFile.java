package interactshbridge;

import com.google.gson.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import static interactshbridge.InteractshClient.*;

/** Password-protected session backup, independent of interaction exports. */
final class SessionFile {
    static byte[] encode(Session s, char[] password) throws GeneralSecurityException {
        if (password.length < 12) throw new IllegalArgumentException("Use a session password of at least 12 characters.");
        JsonObject data = new JsonObject(); data.add("config", JSON.toJsonTree(s.config()));
        data.addProperty("id", s.id()); data.addProperty("secret", s.secret());
        data.addProperty("privateKey", Base64.getEncoder().encodeToString(s.keys().getPrivate().getEncoded()));
        data.addProperty("publicKey", Base64.getEncoder().encodeToString(s.keys().getPublic().getEncoded()));
        byte[] salt = new byte[16], iv = new byte[12]; RANDOM.nextBytes(salt); RANDOM.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(Cipher.ENCRYPT_MODE, key(password, salt), new GCMParameterSpec(128, iv)); cipher.updateAAD("Interactsh-Bridge/session/v1".getBytes(StandardCharsets.US_ASCII));
        byte[] encrypted = cipher.doFinal(data.toString().getBytes(StandardCharsets.UTF_8));
        JsonObject envelope = new JsonObject(); envelope.addProperty("format", "Interactsh-Bridge/session/v1");
        envelope.addProperty("salt", Base64.getEncoder().encodeToString(salt)); envelope.addProperty("iv", Base64.getEncoder().encodeToString(iv)); envelope.addProperty("data", Base64.getEncoder().encodeToString(encrypted));
        return JSON.toJson(envelope).getBytes(StandardCharsets.UTF_8);
    }
    static Session decode(byte[] bytes, char[] password) throws GeneralSecurityException, IOException {
        if (bytes.length > 65536) throw new IOException("Session file exceeds 64 KiB.");
        try {
            JsonObject envelope = JsonParser.parseString(new String(bytes, StandardCharsets.UTF_8)).getAsJsonObject();
            if (!text(envelope, "format").equals("Interactsh-Bridge/session/v1")) throw new IOException("Unsupported session format.");
            byte[] salt = Base64.getDecoder().decode(text(envelope, "salt")), iv = Base64.getDecoder().decode(text(envelope, "iv"));
            if (salt.length != 16 || iv.length != 12) throw new IOException("Invalid session encryption parameters.");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(Cipher.DECRYPT_MODE, key(password, salt), new GCMParameterSpec(128, iv)); cipher.updateAAD("Interactsh-Bridge/session/v1".getBytes(StandardCharsets.US_ASCII));
            JsonObject data = JsonParser.parseString(new String(cipher.doFinal(Base64.getDecoder().decode(text(envelope, "data"))), StandardCharsets.UTF_8)).getAsJsonObject();
            Config config = JSON.fromJson(data.get("config"), Config.class);
            String id = text(data, "id"), secret = text(data, "secret");
            if (config == null || id.length() != config.idLength() || !id.matches("[a-z0-9]+") || secret.isEmpty() || secret.length() > 256) throw new IOException("Invalid session identity.");
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(text(data, "privateKey"))));
            PublicKey publicKey = factory.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(text(data, "publicKey"))));
            if (!((RSAPrivateKey) privateKey).getModulus().equals(((RSAPublicKey) publicKey).getModulus()) || ((RSAPublicKey) publicKey).getModulus().bitLength() != 2048) throw new IOException("Invalid RSA key pair.");
            return new Session(config, id, secret, new KeyPair(publicKey, privateKey));
        } catch (RuntimeException ex) { throw new IOException("Invalid session file.", ex); }
    }
    private static SecretKey key(char[] password, byte[] salt) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, 210000, 256);
        try { byte[] raw = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
            try { return new SecretKeySpec(raw, "AES"); } finally { Arrays.fill(raw, (byte) 0); }
        } finally { spec.clearPassword(); }
    }
}

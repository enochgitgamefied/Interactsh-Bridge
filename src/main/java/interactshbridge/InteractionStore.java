package interactshbridge;

import com.google.gson.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import static interactshbridge.InteractshClient.*;

final class InteractionStore {
    record Entry(JsonObject data, String server, String sessionId) {}
    private final int limit;
    private final LinkedHashMap<String, Entry> entries = new LinkedHashMap<>();
    long evicted;
    private long retainedBytes;
    InteractionStore(int limit) { this.limit = limit; }
    int add(Session session, Poll poll) {
        int added = 0;
        for (JsonObject item : poll.interactions()) {
            if (item == null || !item.has("protocol")) continue;
            String fingerprint = session.id() + session.config().url() + item.toString();
            String hash;
            try { hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(fingerprint.getBytes(StandardCharsets.UTF_8))); }
            catch (GeneralSecurityException ex) { throw new IllegalStateException(ex); }
            if (entries.containsKey(hash)) continue;
            entries.put(hash, new Entry(item.deepCopy(), session.config().url(), session.id())); added++;
            retainedBytes += item.toString().getBytes(StandardCharsets.UTF_8).length;
            while (entries.size() > limit || retainedBytes > 32L * 1024 * 1024) {
                Entry removed = entries.remove(entries.keySet().iterator().next()); retainedBytes -= removed.data().toString().getBytes(StandardCharsets.UTF_8).length; evicted++;
            }
        }
        return added;
    }
    List<Entry> values() { List<Entry> result = new ArrayList<>(entries.values()); Collections.reverse(result); return result; }
    void clear() { entries.clear(); evicted = 0; retainedBytes = 0; }
    JsonObject export(String notes) {
        JsonObject data = new JsonObject(); data.addProperty("format", "Interactsh-Bridge/interactions/v1");
        data.addProperty("notes", notes); data.addProperty("evicted", evicted); data.add("interactions", JSON.toJsonTree(values())); return data;
    }
}

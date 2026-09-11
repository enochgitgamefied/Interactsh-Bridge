package interactshbridge;

import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.*;
import static interactshbridge.InteractshClient.*;

/** Single network worker, immutable sessions, and generation-tagged UI events. */
final class SessionController implements AutoCloseable {
    interface Listener { void connected(Session session, Poll initial); void polled(Poll result); void error(String message); }
    private final ScheduledExecutorService worker = Executors.newSingleThreadScheduledExecutor(r -> daemon(r, "interactsh-bridge-network"));
    private final ExecutorService cleanup = Executors.newSingleThreadExecutor(r -> daemon(r, "interactsh-bridge-cleanup"));
    private final AtomicLong generation = new AtomicLong();
    private final AtomicBoolean manualPending = new AtomicBoolean();
    private final Consumer<Runnable> dispatch;
    private final Listener listener;
    private volatile InteractshClient client;
    private volatile Session session;
    private volatile ScheduledFuture<?> periodic;
    private volatile Future<?> connecting;
    SessionController(Consumer<Runnable> dispatch, Listener listener) { this.dispatch = dispatch; this.listener = listener; }
    static Thread daemon(Runnable task, String name) { Thread t = new Thread(task, name); t.setDaemon(true); return t; }
    Session session() { return session; }
    private void emit(long run, Runnable event) { dispatch.accept(() -> { if (generation.get() == run) event.run(); }); }
    synchronized void connect(Config config, Session restored) {
        if (client != null || connecting != null && !connecting.isDone()) throw new IllegalStateException("Disconnect the current session first.");
        long run = generation.incrementAndGet();
        connecting = worker.submit(() -> {
            InteractshClient current = null;
            try {
                Session candidate = restored == null ? create(config) : restored;
                synchronized (this) {
                    if (generation.get() != run) return;
                    current = new InteractshClient(candidate); client = current;
                }
                current.check();
                Poll first;
                if (restored != null) first = current.resume(); else { current.register(); first = current.poll(); }
                synchronized (this) {
                    if (generation.get() != run) return;
                    session = candidate; connecting = null;
                    emit(run, () -> listener.connected(candidate, first));
                    InteractshClient pollingClient = current;
                    periodic = worker.scheduleWithFixedDelay(() -> poll(run, pollingClient), config.interval(), config.interval(), TimeUnit.SECONDS);
                }
            } catch (Exception ex) {
                if (current != null) current.close();
                synchronized (this) {
                    if (generation.get() == run) { client = null; session = null; connecting = null; emit(run, () -> listener.error("Connection failed: " + safe(ex))); }
                }
            }
        });
    }
    private void poll(long run, InteractshClient current) {
        if (generation.get() != run) return;
        try { Poll result = current.poll(); emit(run, () -> listener.polled(result)); }
        catch (Exception ex) { emit(run, () -> listener.error("Poll failed: " + safe(ex))); }
    }
    void pollNow() {
        Session active = session; InteractshClient current = client; long run = generation.get();
        if (active == null || current == null || !manualPending.compareAndSet(false, true)) return;
        worker.execute(() -> { try { poll(run, current); } finally { manualPending.set(false); } });
    }
    synchronized void disconnect(boolean deregister) {
        generation.incrementAndGet();
        ScheduledFuture<?> repeating = periodic; periodic = null; if (repeating != null) repeating.cancel(true);
        Future<?> pending = connecting; connecting = null; if (pending != null) pending.cancel(true);
        InteractshClient previous = client; client = null; session = null;
        if (previous != null) cleanup.execute(() -> {
            previous.close();
            if (deregister) try (InteractshClient finish = new InteractshClient(previous.session)) { finish.deregister(); }
            catch (Exception ignored) { /* best effort; local session is already stopped */ }
        });
    }
    @Override public void close() { disconnect(false); worker.shutdownNow(); cleanup.shutdown(); }
    static String safe(Exception ex) {
        if (ex instanceof javax.net.ssl.SSLException) return "TLS verification failed. Use a trusted server certificate or configure the Java trust store.";
        if (ex instanceof java.net.ConnectException) return "Unable to connect. Check the server URL and availability.";
        if (ex instanceof java.net.UnknownHostException) return "Server hostname could not be resolved.";
        if (ex instanceof CancellationException || ex instanceof InterruptedException) return "Operation cancelled.";
        if (ex instanceof java.io.IOException || ex instanceof IllegalArgumentException) return ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage();
        return ex.getClass().getSimpleName() + ". Check the server configuration.";
    }
}

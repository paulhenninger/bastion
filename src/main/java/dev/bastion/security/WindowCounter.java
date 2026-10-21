package dev.bastion.security;

import java.time.Clock;
import java.time.Duration;
import java.util.Comparator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Fixed-window counters keyed by string, with a hard bound on memory. The single
 * primitive under every limiter in the app (per-IP request limits, per-account
 * login failures, per-account code guesses, per-recipient mail).
 *
 * <p>In-memory by design: Bastion assumes one instance. Running several means
 * moving these counters to a shared store (Redis {@code INCR} + {@code EXPIRE} is
 * the drop-in) — see docs/operations.md.
 *
 * <p>{@code maxKeys} is a hard bound, not just a prune trigger. Under the traffic a
 * bound exists for — a spray across rotating IPs or addresses — every entry is
 * fresh, so pruning only expired ones would remove nothing. The oldest windows go
 * too: handing one caller back a window they could have had by waiting beats
 * letting an attacker spend the server's memory.
 */
public final class WindowCounter {

    private final Duration window;
    private final int maxKeys;
    private final Clock clock;
    private final Map<String, Window> windows = new ConcurrentHashMap<>();

    public WindowCounter(Duration window, int maxKeys) {
        this(window, maxKeys, Clock.systemUTC());
    }

    WindowCounter(Duration window, int maxKeys, Clock clock) {
        this.window = window;
        this.maxKeys = maxKeys;
        this.clock = clock;
    }

    /** Adds one to {@code key}'s window and returns the new count. */
    public int increment(String key) {
        long now = clock.millis();
        Window w = windows.compute(key, (k, existing) ->
                existing == null || expired(existing, now) ? new Window(now, 1) : existing.plusOne());
        if (windows.size() > maxKeys) {
            evict(now);
        }
        return w.count();
    }

    /** The current count for {@code key} (0 when absent or expired). */
    public int count(String key) {
        Window w = windows.get(key);
        return w == null || expired(w, clock.millis()) ? 0 : w.count();
    }

    /** Seconds until {@code key}'s window resets — for a {@code Retry-After} header. */
    public long secondsUntilReset(String key) {
        Window w = windows.get(key);
        if (w == null) {
            return 0;
        }
        long remaining = w.startMs() + window.toMillis() - clock.millis();
        return Math.max(1, (remaining + 999) / 1000);
    }

    public void reset(String key) {
        windows.remove(key);
    }

    private boolean expired(Window w, long now) {
        return now - w.startMs() >= window.toMillis();
    }

    private synchronized void evict(long now) {
        if (windows.size() <= maxKeys) {
            return;
        }
        windows.entrySet().removeIf(e -> expired(e.getValue(), now));
        int excess = windows.size() - maxKeys;
        if (excess > 0) {
            windows.entrySet().stream()
                    .sorted(Comparator.comparingLong(e -> e.getValue().startMs()))
                    .limit(excess)
                    .map(Map.Entry::getKey)
                    .toList()
                    .forEach(windows::remove);
        }
    }

    int size() {
        return windows.size();
    }

    private record Window(long startMs, int count) {
        Window plusOne() {
            return new Window(startMs, count + 1);
        }
    }
}

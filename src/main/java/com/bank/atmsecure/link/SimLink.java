package com.bank.atmsecure.link;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * In-process model of the RS-485-style cable between the terminal PC and the dispenser. It carries
 * only opaque bytes; the two endpoints speak through it and never call each other directly.
 *
 * <p>Keeping the link a first-class object is what makes the black-box tests honest: an attacker
 * installs a tap with {@link #installTap()} and then sees exactly the bytes a soldered-on laptop would
 * see, via {@link #observed()} — no more, no less. Nothing here holds key material, mirroring the
 * reality that the attacker owns the wire, not the protocol secrets.
 */
public final class SimLink {
    private final List<byte[]> tapped = new ArrayList<>();
    private final Consumer<String> trace;
    private boolean tapInstalled;

    public SimLink() {
        this(null);
    }

    public SimLink(Consumer<String> trace) {
        this.trace = trace;
    }

    /** Attacker solders a tap onto the line: from now on every byte is recorded. */
    public void installTap() {
        tapInstalled = true;
    }

    /** Everything the tap has seen, in transmission order. */
    public List<byte[]> observed() {
        return List.copyOf(tapped);
    }

    public void clearObserved() {
        tapped.clear();
    }

    /** Puts a frame on the wire. Records it if a tap is installed. */
    public void transmit(byte[] bytes) {
        if (tapInstalled) {
            tapped.add(bytes.clone());
        }
    }

    public void log(String msg) {
        if (trace != null) {
            trace.accept(msg);
        }
    }
}

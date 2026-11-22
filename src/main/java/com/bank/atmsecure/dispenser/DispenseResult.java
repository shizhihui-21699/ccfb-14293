package com.bank.atmsecure.dispenser;

import com.bank.atmsecure.auth.DispenseReceipt;
import com.bank.atmsecure.crypto.Canonical;

/**
 * Dispenser → terminal: outcome plus, on success, the module-signed receipt.
 *
 * <p>On failure {@code receipt} is null and {@code status} carries the coarse reason. The module never
 * returns cash without a receipt; the receipt is produced in the same step that drives the transport.
 */
public record DispenseResult(DispenseStatus status, DispenseReceipt receipt, String detail) {

    public static DispenseResult ok(DispenseReceipt r) {
        return new DispenseResult(DispenseStatus.OK, r, "");
    }

    public static DispenseResult refused(DispenseStatus s, String detail) {
        return new DispenseResult(s, null, detail == null ? "" : detail);
    }

    public boolean ok() {
        return status.ok() && receipt != null;
    }

    public byte[] encode() {
        Canonical.Writer w = new Canonical.Writer();
        w.u8(status.code());
        w.bool(receipt != null);
        if (receipt != null) {
            w.bytes(receipt.encode());
        }
        w.str(detail);
        return w.toByteArray();
    }

    public static DispenseResult decode(byte[] raw) {
        Canonical.Reader r = new Canonical.Reader(raw);
        DispenseStatus status = DispenseStatus.fromCode(r.u8());
        boolean hasReceipt = r.bool();
        DispenseReceipt receipt = hasReceipt ? DispenseReceipt.decode(r.bytes()) : null;
        String detail = r.str();
        r.expectEnd();
        if (status.ok() != hasReceipt) {
            throw new IllegalArgumentException("result status/receipt inconsistency");
        }
        return new DispenseResult(status, receipt, detail);
    }

    @Override
    public String toString() {
        return ok() ? "OK " + receipt : "REFUSED " + status
                + (detail.isEmpty() ? "" : " (" + detail + ")");
    }
}

package com.bank.atmsecure.dispenser;

import com.bank.atmsecure.auth.HostAuthorization;
import com.bank.atmsecure.auth.OfflineEnvelope;
import com.bank.atmsecure.crypto.Canonical;
import com.bank.atmsecure.model.CashPlan;
import com.bank.atmsecure.model.ModuleId;
import com.bank.atmsecure.model.TerminalId;
import com.bank.atmsecure.model.TxId;

/**
 * Terminal → dispenser request. Two shapes, because online and offline authority are fundamentally
 * different and must not be conflated:
 *
 * <ul>
 *   <li>{@link Online}: carries a host-signed {@link HostAuthorization}. The module trusts nothing the
 *       terminal says; the plan, amount, nonce, channel binding, sequence and expiry are all inside
 *       the host signature.</li>
 *   <li>{@link Offline}: carries a host-signed {@link OfflineEnvelope} plus a plan the terminal chose
 *       <em>within</em> the envelope's per-transaction cap. There is no per-transaction host
 *       signature by construction; the envelope's budget/count/expiry limits and the module's
 *       rollback-protected counters are what bound the damage. The receipt records the real plan so
 *       the host can reconcile.</li>
 * </ul>
 */
public sealed interface DispenseRequest permits DispenseRequest.Online, DispenseRequest.Offline {

    CashPlan plan();

    byte[] encode();

    static DispenseRequest decode(byte[] raw) {
        Canonical.Reader r = new Canonical.Reader(raw);
        int tag = r.u8();
        DispenseRequest req;
        if (tag == 1) {
            req = new Online(HostAuthorization.decode(r.bytes()));
        } else if (tag == 2) {
            OfflineEnvelope env = OfflineEnvelope.decode(r.bytes());
            CashPlan plan = CashPlan.decode(r);
            req = new Offline(env, plan);
        } else {
            throw new IllegalArgumentException("unknown dispense request tag " + tag);
        }
        r.expectEnd();
        return req;
    }

    record Online(HostAuthorization authorization) implements DispenseRequest {
        @Override
        public CashPlan plan() {
            return authorization.plan();
        }

        @Override
        public byte[] encode() {
            Canonical.Writer w = new Canonical.Writer();
            w.u8(1);
            w.bytes(authorization.encode());
            return w.toByteArray();
        }

        public TxId txId() {
            return authorization.txId();
        }

        public ModuleId moduleId() {
            return authorization.moduleId();
        }
    }

    record Offline(OfflineEnvelope envelope, CashPlan plan) implements DispenseRequest {
        @Override
        public byte[] encode() {
            Canonical.Writer w = new Canonical.Writer();
            w.u8(2);
            w.bytes(envelope.encode());
            plan.encode(w);
            return w.toByteArray();
        }

        public TerminalId terminalId() {
            return envelope.terminalId();
        }

        public ModuleId moduleId() {
            return envelope.moduleId();
        }
    }
}

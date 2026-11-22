package com.bank.atmsecure.host;

import com.bank.atmsecure.auth.DispenseReceipt;
import com.bank.atmsecure.auth.HostAuthorization;
import com.bank.atmsecure.auth.OfflineEnvelope;
import com.bank.atmsecure.auth.PairingGrant;
import com.bank.atmsecure.crypto.CryptoException;
import com.bank.atmsecure.crypto.Ed25519;
import com.bank.atmsecure.model.CashPlan;
import com.bank.atmsecure.model.ModuleId;
import com.bank.atmsecure.model.Money;
import com.bank.atmsecure.model.Protocol;
import com.bank.atmsecure.model.TerminalId;
import com.bank.atmsecure.model.TxId;
import com.bank.atmsecure.security.SimClock;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * The host: business authorisation, policy, signing via {@link HostHsm}, and reconciliation.
 *
 * <p>This is where the "does this transaction get to happen" decision lives. A request arrives from a
 * terminal that may be honest or may be entirely attacker-controlled; the host does not trust any
 * field it cannot cross-check against its own ledger, and it never exposes a method that signs an
 * arbitrary blob.
 */
public final class Host {
    private final HostHsm hsm;
    private final HostLedger ledger;
    private final HostPolicy policy;
    private final SimClock clock;

    public Host(HostHsm hsm, HostLedger ledger, HostPolicy policy, SimClock clock) {
        policy.validate();
        this.hsm = hsm;
        this.ledger = ledger;
        this.policy = policy;
        this.clock = clock;
    }

    public HostHsm hsm() {
        return hsm;
    }

    public HostLedger ledger() {
        return ledger;
    }

    public HostPolicy policy() {
        return policy;
    }

    public void provisionModule(ModuleId moduleId, TerminalId terminalId, int keyEpoch,
            byte[] modulePublicKey, String serial) {
        ledger.registerModule(new HostLedger.ModuleRecord(moduleId, terminalId, keyEpoch,
                modulePublicKey.clone(), serial));
    }

    /** Authorisation request as the terminal would present it — all fields treated as untrusted. */
    public record OnlineRequest(TerminalId terminalId, ModuleId moduleId, int keyEpoch, TxId txId,
            String customerId, Money amount, CashPlan plan, byte[] nonce, byte[] channelBinding) {
        public void validateFields() {
            if (terminalId == null || moduleId == null || txId == null || customerId == null
                    || amount == null || plan == null || nonce == null || channelBinding == null) {
                throw new IllegalArgumentException("missing request field");
            }
            if (nonce.length != Protocol.NONCE_BYTES) {
                throw new IllegalArgumentException("nonce wrong length");
            }
            if (channelBinding.length != Protocol.CHANNEL_BINDING_BYTES) {
                throw new IllegalArgumentException("channel binding wrong length");
            }
        }
    }

    public record Decision(boolean approved, HostAuthorization authorization, String reason) {
        static Decision refuse(String reason) {
            return new Decision(false, null, reason);
        }
    }

    /**
     * Approves or refuses an online dispense and, if approved, returns the signed authorisation.
     *
     * <p>Cross-checks against the ledger are the important part: the terminal-supplied module id and
     * epoch must match a provisioned pairing, the amount must equal the plan, and daily limits are
     * whatever the host itself has recorded — not anything the terminal claims.
     */
    public synchronized Decision authorize(OnlineRequest req) {
        req.validateFields();
        HostLedger.ModuleRecord rec = ledger.module(req.moduleId());
        if (rec == null) {
            return Decision.refuse("module not provisioned");
        }
        if (!rec.terminalId().equals(req.terminalId())) {
            return Decision.refuse("module paired to a different terminal");
        }
        if (rec.keyEpoch() != req.keyEpoch()) {
            return Decision.refuse("pairing epoch mismatch");
        }
        if (req.amount().cents() != req.plan().totalCents()) {
            return Decision.refuse("amount does not match plan");
        }
        if (req.amount().cents() <= 0 || !req.amount().atMost(policy.maxOnlinePerTransaction())) {
            return Decision.refuse("amount exceeds online transaction limit");
        }
        long epochDay = clock.millis() / 86_400_000L;
        HostPolicy.DailyKey key = new HostPolicy.DailyKey(req.terminalId(), req.customerId(), epochDay);
        Money spent = ledger.spentToday(key);
        if (spent.plus(req.amount()).cents() > policy.maxOnlinePerDay().cents()) {
            return Decision.refuse("daily spend limit exceeded");
        }
        if (ledger.txCountToday(key) >= policy.maxOnlineTransactionsPerDay()) {
            return Decision.refuse("daily transaction count exceeded");
        }

        long now = clock.millis();
        long seq = ledger.nextSequence(req.moduleId());
        HostAuthorization auth = HostAuthorization.builder()
                .moduleId(req.moduleId())
                .terminalId(req.terminalId())
                .txId(req.txId())
                .amount(req.amount())
                .plan(req.plan())
                .nonce(req.nonce())
                .channelBinding(req.channelBinding())
                .seq(seq)
                .validity(now, now + policy.authorizationValidityMillis())
                .keyEpoch(req.keyEpoch())
                .build();
        HostAuthorization signed = hsm.signAuthorization(auth);
        ledger.recordSpend(key, req.amount());
        return new Decision(true, signed, "");
    }

    public record OfflineIssueRequest(ModuleId moduleId, TerminalId terminalId, int keyEpoch,
            Money budget, Money perTxMax, int maxTransactions, long seqWindow) {
    }

    /**
     * Issues an offline envelope before connectivity is lost. The host picks the budget and limits; the
     * terminal cannot influence them. The envelope carries <em>absolute</em> lifetime ceilings on the
     * module's cumulative offline spend and count, computed from the host's last reconciled view plus
     * the grant. Because a rollback of the module's NVRAM cannot lower its OTP-anchored cumulative
     * spend, replaying this envelope after a rollback yields no extra money.
     */
    public synchronized OfflineEnvelope issueOfflineEnvelope(OfflineIssueRequest req) {
        if (!policy.allowOffline()) {
            throw new CryptoException("offline mode disabled by policy");
        }
        HostLedger.ModuleRecord rec = ledger.module(req.moduleId());
        if (rec == null || !rec.terminalId().equals(req.terminalId())
                || rec.keyEpoch() != req.keyEpoch()) {
            throw new CryptoException("module not provisioned for this terminal/epoch");
        }
        if (req.budget().cents() > policy.maxOfflineBudget().cents()
                || req.perTxMax().cents() > policy.maxOfflinePerTransaction().cents()) {
            throw new CryptoException("offline envelope exceeds policy");
        }
        if (req.maxTransactions() <= 0 || req.maxTransactions() > policy.maxOfflineTransactions()) {
            throw new CryptoException("offline transaction count exceeds policy");
        }
        long now = clock.millis();
        String envelopeId = "ENV-" + req.moduleId().value() + "-" + UUID.randomUUID();
        long baseSpent = ledger.reconciledOfflineSpend(req.moduleId());
        long baseCount = ledger.reconciledOfflineCount(req.moduleId());
        long spendCap = baseSpent + req.budget().cents();
        long countCap = baseCount + req.maxTransactions();
        long seqStart = ledger.nextSequence(req.moduleId());
        long seqEnd = seqStart + req.seqWindow();
        for (long i = seqStart + 1; i <= seqEnd; i++) {
            ledger.nextSequence(req.moduleId());
        }
        OfflineEnvelope template = OfflineEnvelope.builder()
                .envelopeId(envelopeId)
                .moduleId(req.moduleId())
                .terminalId(req.terminalId())
                .keyEpoch(req.keyEpoch())
                .perTxMax(req.perTxMax())
                .spendCapCents(spendCap)
                .txCountCap(countCap)
                .grantedBudget(req.budget())
                .grantedTransactions(req.maxTransactions())
                .seqWindow(seqStart, seqEnd)
                .validity(now, now + policy.offlineValidityMillis())
                .build();
        OfflineEnvelope signed = hsm.signEnvelope(template);
        ledger.recordEnvelope(new HostLedger.EnvelopeRecord(envelopeId, req.moduleId(),
                req.keyEpoch(), req.budget(), req.maxTransactions(),
                now + policy.offlineValidityMillis()));
        return signed;
    }

    public synchronized PairingGrant.IssuedPairing issuePairingGrant(ModuleId moduleId,
            TerminalId terminalId, int newEpoch, String technicianId, String workOrderId) {
        long now = clock.millis();
        String grantId = "PG-" + moduleId.value() + "-" + newEpoch + "-" + UUID.randomUUID();
        PairingGrant grant = PairingGrant.builder()
                .grantId(grantId)
                .moduleId(moduleId)
                .terminalId(terminalId)
                .technicianId(technicianId)
                .workOrderId(workOrderId)
                .newKeyEpoch(newEpoch)
                .validity(now, now + 10 * 60_000L)
                .build();
        PairingGrant signed = hsm.signPairingGrant(grant);
        // Record the new pairing only after the module accepts; the ledger update is the last step.
        return new PairingGrant.IssuedPairing(signed, (ok) -> {
            if (ok) {
                HostLedger.ModuleRecord old = ledger.module(moduleId);
                ledger.registerModule(new HostLedger.ModuleRecord(moduleId, terminalId, newEpoch,
                        old == null ? new byte[0] : old.modulePublicKey(),
                        old == null ? "" : old.serial()));
            }
        });
    }

    // ---------------------------------------------------------------------------------------------
    // Reconciliation
    // ---------------------------------------------------------------------------------------------

    public record ReconciliationResult(int accepted, int rejected, List<String> problems) {
    }

    /**
     * Settles a batch of receipts (delivered when the link comes back). Verifies each module
     * signature, the receipt hash chain and per-envelope budget, and flags anything that does not add
     * up. This is how offline damage is bounded even if a module is later found to have been replaced.
     */
    public synchronized ReconciliationResult reconcile(ModuleId moduleId,
            List<DispenseReceipt> receipts) {
        HostLedger.ModuleRecord rec = ledger.module(moduleId);
        List<String> problems = new ArrayList<>();
        if (rec == null) {
            problems.add("unknown module " + moduleId);
            return new ReconciliationResult(0, receipts.size(), problems);
        }
        java.security.PublicKey moduleKey = Ed25519.fromRawPublic(rec.modulePublicKey());
        int accepted = 0;
        int rejected = 0;
        byte[] expectedPrev = null;
        long lastModuleSeq = -1;
        for (DispenseReceipt r : receipts) {
            if (!r.moduleId().equals(moduleId)) {
                problems.add("receipt for other module: " + r.txId());
                rejected++;
                continue;
            }
            if (!r.verifySignature(moduleKey)) {
                problems.add("bad receipt signature: " + r.txId());
                rejected++;
                continue;
            }
            if (lastModuleSeq >= 0 && r.moduleSeq() != lastModuleSeq + 1) {
                problems.add("receipt chain gap: expected seq " + (lastModuleSeq + 1)
                        + " got " + r.moduleSeq() + " (" + r.txId() + ")");
                // Do not abort: record and continue so the bank sees the whole picture.
            }
            if (expectedPrev != null && !java.util.Arrays.equals(r.prevReceiptHash(), expectedPrev)) {
                problems.add("receipt hash chain broken at " + r.txId());
            }
            if (!ledger.markTransactionSettled(r.txId())) {
                problems.add("duplicate settlement (replayed receipt): " + r.txId());
                rejected++;
                continue;
            }
            if (r.offline()) {
                if (!ledger.wasEnvelopeIssued(r.offlineEnvelopeId())) {
                    problems.add("offline receipt for unknown envelope: " + r.offlineEnvelopeId());
                    rejected++;
                    continue;
                }
                if (r.amountCents() > policy.maxOfflinePerTransaction().cents()) {
                    problems.add("offline receipt over per-tx cap: " + r.txId());
                    rejected++;
                    continue;
                }
                ledger.markEnvelopeSettled(r.offlineEnvelopeId());
                ledger.recordReconciledOffline(moduleId,
                        ledger.reconciledOfflineSpend(moduleId) + r.amountCents(),
                        ledger.reconciledOfflineCount(moduleId) + 1);
            }
            lastModuleSeq = r.moduleSeq();
            expectedPrev = r.hash();
            accepted++;
        }
        for (String p : problems) {
            ledger.recordSettlementIssue(new HostLedger.SettlementIssue("RECONCILE", moduleId,
                    null, Money.ofCents(0), p));
        }
        return new ReconciliationResult(accepted, rejected, problems);
    }

    /** Summarises a dispenser's reported state against the host's expectations. */
    public synchronized List<String> auditModuleState(ModuleId moduleId, long reportedSeqHighWater,
            long reportedReceiptSeq) {
        List<String> issues = new ArrayList<>();
        long hostSeq = ledger.currentSequence(moduleId);
        if (reportedSeqHighWater > hostSeq) {
            issues.add("module high-water " + reportedSeqHighWater
                    + " is ahead of host allocation " + hostSeq + " — possibly forged/spoofed");
        }
        if (reportedReceiptSeq > hostSeq + 10_000) {
            issues.add("receipt sequence implausibly high: " + reportedReceiptSeq);
        }
        return issues;
    }
}

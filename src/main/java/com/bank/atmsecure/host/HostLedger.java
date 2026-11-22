package com.bank.atmsecure.host;

import com.bank.atmsecure.model.Money;
import com.bank.atmsecure.model.ModuleId;
import com.bank.atmsecure.model.TerminalId;
import com.bank.atmsecure.model.TxId;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Host-side durable state: which modules are provisioned, per-customer/day spend, which offline
 * envelopes have been issued and which have been settled, and the monotone sequence allocated to each
 * module.
 *
 * <p>Sequence numbers are allocated here, at the host, and never reused. The dispenser enforces that
 * sequence numbers strictly increase, so an authorisation the host once minted can never be valid a
 * second time even if its bytes leak. A compromised terminal cannot "guess ahead" to a future sequence
 * and have it work, because the signature covers the exact sequence.
 */
public final class HostLedger {
    public record ModuleRecord(ModuleId moduleId, TerminalId terminalId, int keyEpoch,
            byte[] modulePublicKey, String serial) {
    }

    public record EnvelopeRecord(String envelopeId, ModuleId moduleId, int keyEpoch, Money budget,
            int maxTransactions, long expiresAtMillis) {
    }

    public record SettlementIssue(String kind, ModuleId moduleId, TxId txId, Money amount,
            String detail) {
    }

    private final Map<ModuleId, ModuleRecord> modules = new HashMap<>();
    private final Map<ModuleId, Long> sequenceByModule = new HashMap<>();
    private final Map<HostPolicy.DailyKey, Money> spentToday = new HashMap<>();
    private final Map<HostPolicy.DailyKey, Integer> txCountToday = new HashMap<>();
    private final Map<String, EnvelopeRecord> issuedEnvelopes = new HashMap<>();
    private final Set<String> settledEnvelopes = new HashSet<>();
    private final Set<TxId> settledTransactions = new HashSet<>();
    private final List<SettlementIssue> settlementIssues = new ArrayList<>();
    private final Map<ModuleId, Long> reconciledOfflineSpend = new HashMap<>();
    private final Map<ModuleId, Long> reconciledOfflineCount = new HashMap<>();

    public synchronized void registerModule(ModuleRecord rec) {
        modules.put(rec.moduleId(), rec);
        sequenceByModule.putIfAbsent(rec.moduleId(), 0L);
    }

    public synchronized ModuleRecord module(ModuleId id) {
        return modules.get(id);
    }

    public synchronized boolean isProvisioned(ModuleId id) {
        return modules.containsKey(id);
    }

    public synchronized long nextSequence(ModuleId id) {
        long next = sequenceByModule.merge(id, 1L, Long::sum);
        return next;
    }

    public synchronized long currentSequence(ModuleId id) {
        return sequenceByModule.getOrDefault(id, 0L);
    }

    /** Allocates and records an offline envelope so it can never be issued twice. */
    public synchronized void recordEnvelope(EnvelopeRecord rec) {
        if (issuedEnvelopes.putIfAbsent(rec.envelopeId(), rec) != null) {
            throw new IllegalStateException("envelope id reused: " + rec.envelopeId());
        }
    }

    public synchronized boolean wasEnvelopeIssued(String envelopeId) {
        return issuedEnvelopes.containsKey(envelopeId);
    }

    public synchronized boolean wasEnvelopeSettled(String envelopeId) {
        return settledEnvelopes.contains(envelopeId);
    }

    public synchronized boolean markEnvelopeSettled(String envelopeId) {
        return settledEnvelopes.add(envelopeId);
    }

    public synchronized boolean markTransactionSettled(TxId txId) {
        return settledTransactions.add(txId);
    }

    public synchronized Money spentToday(HostPolicy.DailyKey key) {
        return spentToday.getOrDefault(key, Money.ofCents(0));
    }

    public synchronized int txCountToday(HostPolicy.DailyKey key) {
        return txCountToday.getOrDefault(key, 0);
    }

    public synchronized void recordSpend(HostPolicy.DailyKey key, Money amount) {
        spentToday.merge(key, amount, Money::plus);
        txCountToday.merge(key, 1, Integer::sum);
    }

    public synchronized void recordSettlementIssue(SettlementIssue issue) {
        settlementIssues.add(issue);
    }

    public synchronized List<SettlementIssue> settlementIssues() {
        return List.copyOf(settlementIssues);
    }

    public synchronized void clearSettlementIssues() {
        settlementIssues.clear();
    }

    public synchronized List<EnvelopeRecord> envelopesFor(ModuleId id) {
        List<EnvelopeRecord> out = new ArrayList<>();
        for (EnvelopeRecord r : issuedEnvelopes.values()) {
            if (r.moduleId().equals(id)) {
                out.add(r);
            }
        }
        return out;
    }

    public synchronized long reconciledOfflineSpend(ModuleId id) {
        return reconciledOfflineSpend.getOrDefault(id, 0L);
    }

    public synchronized long reconciledOfflineCount(ModuleId id) {
        return reconciledOfflineCount.getOrDefault(id, 0L);
    }

    /** Advances the host's view of a module's cumulative offline spend after reconciliation. */
    public synchronized void recordReconciledOffline(ModuleId id, long cumulativeSpendCents,
            long cumulativeCount) {
        reconciledOfflineSpend.merge(id, cumulativeSpendCents, Math::max);
        reconciledOfflineCount.merge(id, cumulativeCount, Math::max);
    }
}

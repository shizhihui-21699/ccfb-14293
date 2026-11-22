package com.bank.atmsecure.host;

import com.bank.atmsecure.model.ModuleId;
import com.bank.atmsecure.model.Money;
import com.bank.atmsecure.model.TerminalId;

/**
 * Bank policy applied <em>before</em> the HSM is asked to sign. This is the business layer's
 * authority question ("is this customer allowed to take this money?") as opposed to the
 * cryptographic one ("is this message authentically from the bank?").
 *
 * <p>Keeping the two separate matters for the black-box threat: even a terminal that fully
 * compromises the business layer can only ask the host for authorisations the host itself approves.
 * The host is the trust anchor; the terminal is not trusted to decide.
 */
public record HostPolicy(
        Money maxOnlinePerTransaction,
        Money maxOnlinePerDay,
        int maxOnlineTransactionsPerDay,
        Money maxOfflinePerTransaction,
        Money maxOfflineBudget,
        int maxOfflineTransactions,
        long authorizationValidityMillis,
        long offlineValidityMillis,
        boolean allowOffline) {

    public static HostPolicy standard() {
        return new HostPolicy(
                Money.ofYuan(5_000),
                Money.ofYuan(20_000),
                10,
                Money.ofYuan(1_000),
                Money.ofYuan(3_000),
                3,
                60_000L,
                30 * 60_000L,
                true);
    }

    public void validate() {
        if (maxOnlinePerTransaction.cents() <= 0 || maxOfflinePerTransaction.cents() <= 0) {
            throw new IllegalArgumentException("non-positive transaction cap");
        }
        if (maxOfflinePerTransaction.cents() > maxOnlinePerTransaction.cents()) {
            throw new IllegalArgumentException("offline cap must not exceed online cap");
        }
        if (maxOfflineBudget.cents() > maxOnlinePerDay.cents()) {
            throw new IllegalArgumentException("offline budget must not exceed daily limit");
        }
        if (authorizationValidityMillis <= 0 || offlineValidityMillis <= 0) {
            throw new IllegalArgumentException("non-positive validity");
        }
    }

    /** Per-day accounting key. */
    public record DailyKey(TerminalId terminalId, String customerId, long epochDay) {
    }

    public record OfflineTrack(ModuleId moduleId, int keyEpoch) {
    }
}

package com.bank.atmsecure.integration;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.bank.atmsecure.model.CashPlan;
import com.bank.atmsecure.model.Denomination;
import com.bank.atmsecure.model.TxId;
import com.bank.atmsecure.security.AuditChain;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class AuditChainTest {

    @Test
    @DisplayName("Hash-chained log detects a deleted or edited entry")
    void tamperEvident() {
        AuditChain log = new AuditChain(64);
        long t = 1000;
        for (int i = 0; i < 10; i++) {
            log.append(t++, AuditChain.Kind.DISPENSE_OK, "tx-" + i);
        }
        List<AuditChain.Entry> entries = new ArrayList<>(log.recent());
        assertTrue(log.verifyChain(entries));

        // Delete an entry.
        List<AuditChain.Entry> deleted = new ArrayList<>(entries);
        deleted.remove(5);
        assertFalse(log.verifyChain(deleted));

        // Edit a detail.
        List<AuditChain.Entry> edited = new ArrayList<>(entries);
        AuditChain.Entry e = edited.get(3);
        edited.set(3, new AuditChain.Entry(e.index(), e.atMillis(), e.kind(), "forged",
                e.prevHash(), e.hash()));
        assertFalse(log.verifyChain(edited));
    }

    @Test
    @DisplayName("The chain continues across a reboot (restore seeds tip and index)")
    void continuousAcrossReboot() {
        AuditChain log = new AuditChain(64);
        for (int i = 0; i < 5; i++) {
            log.append(i, AuditChain.Kind.DISPENSE_OK, "tx-" + i);
        }
        byte[] tip = log.tip();
        long index = log.nextIndex();

        AuditChain rebooted = new AuditChain(64);
        rebooted.restore(tip, index);
        rebooted.append(99, AuditChain.Kind.SESSION_OPENED, "boot");
        assertTrue(rebooted.nextIndex() > index);
    }
}

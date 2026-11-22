package com.bank.atmsecure.sim;

import com.bank.atmsecure.auth.ModuleCertificate;
import com.bank.atmsecure.auth.PairingGrant;
import com.bank.atmsecure.crypto.Ed25519;
import com.bank.atmsecure.dispenser.CashDispenserModule;
import com.bank.atmsecure.host.Host;
import com.bank.atmsecure.host.HostHsm;
import com.bank.atmsecure.host.HostLedger;
import com.bank.atmsecure.host.HostPolicy;
import com.bank.atmsecure.link.Simulator;
import com.bank.atmsecure.model.Denomination;
import com.bank.atmsecure.model.ModuleId;
import com.bank.atmsecure.model.TerminalId;
import com.bank.atmsecure.security.SimClock;
import java.security.KeyPair;

/**
 * A complete, honest deployment of one ATM: bank HSM, host, dispenser module, terminal, link.
 * Tests build on this and then break one thing at a time.
 */
public final class AtmScenario {
    public static final String START = "2026-06-01T09:00:00Z";

    public final SimClock clock;
    public final HostHsm hsm;
    public final HostLedger ledger;
    public final HostPolicy policy;
    public final Host host;
    public final ModuleId moduleId;
    public final TerminalId terminalId;
    public final KeyPair moduleKeys;
    public final ModuleCertificate certificate;
    public final CashDispenserModule module;
    public final Simulator simulator;

    private AtmScenario(Builder b) {
        this.clock = b.clock;
        this.hsm = b.hsm;
        this.moduleId = b.moduleId;
        this.terminalId = b.terminalId;
        this.moduleKeys = b.moduleKeys;
        this.certificate = b.certificate;
        this.ledger = new HostLedger();
        this.policy = b.policy;
        this.host = new Host(hsm, ledger, policy, clock);
        this.module = new CashDispenserModule(b.moduleId, b.moduleKeys, b.certificate,
                hsm.authorizationPublicKey(), hsm.servicePublicKey(), clock);
        // Seed cassettes generously so tests about authorisation are not accidentally about stock.
        for (Denomination d : Denomination.values()) {
            module.cassettes().load(d, 1000);
        }
        module.provisionAtFactory();
        this.simulator = new Simulator(moduleId, module, terminalId, certificate,
                hsm.manufacturingPublicKey(), b.trace);
        host.provisionModule(moduleId, terminalId, 1, Ed25519.rawPublic(moduleKeys.getPublic()),
                b.serial);
        module.boot();
        // Initial installation pairing at the ATM. The module ships unpaired; the technician binds it
        // to the terminal at epoch 1 with the service jumper closed.
        PairingGrant.IssuedPairing initial =
                host.issuePairingGrant(moduleId, terminalId, 1, "TECH-0", "INSTALL-001");
        CashDispenserModule.PairingOutcome paired = module.pair(initial.grant(), true);
        if (!paired.accepted()) {
            throw new IllegalStateException("initial pairing failed: " + paired.reason());
        }
        initial.commit().accept(true);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static AtmScenario standard() {
        return builder().build();
    }

    public Simulator.DispenserSide side() {
        return simulator.dispenserSide();
    }

    public static final class Builder {
        private SimClock clock = SimClock.at(START);
        private HostHsm hsm = new HostHsm();
        private ModuleId moduleId = new ModuleId("DISP-001");
        private TerminalId terminalId = new TerminalId("ATM-0001");
        private String serial = "SN-2026-0001";
        private HostPolicy policy = HostPolicy.standard();
        private java.util.function.Consumer<String> trace;
        private KeyPair moduleKeys = Ed25519.generate();

        private ModuleCertificate certificate;

        public Builder clock(SimClock c) {
            this.clock = c;
            return this;
        }

        public Builder hsm(HostHsm h) {
            this.hsm = h;
            return this;
        }

        public Builder moduleId(String id) {
            this.moduleId = new ModuleId(id);
            return this;
        }

        public Builder terminalId(String id) {
            this.terminalId = new TerminalId(id);
            return this;
        }

        public Builder policy(HostPolicy p) {
            this.policy = p;
            return this;
        }

        public Builder trace(java.util.function.Consumer<String> t) {
            this.trace = t;
            return this;
        }

        public AtmScenario build() {
            this.certificate = hsm.manufactureModuleCertificate(moduleId, moduleKeys.getPublic(),
                    serial, clock.millis());
            return new AtmScenario(this);
        }
    }

    /** Pairing helper: host issues a grant, module accepts it with the jumper closed. */
    public PairingGrant.IssuedPairing issueAndAcceptPairing(TerminalId newTerminal, int newEpoch) {
        PairingGrant.IssuedPairing issued = host.issuePairingGrant(moduleId, newTerminal, newEpoch,
                "TECH-7", "WO-" + newEpoch);
        CashDispenserModule.PairingOutcome outcome =
                module.pair(issued.grant(), true);
        issued.commit().accept(outcome.accepted());
        if (!outcome.accepted()) {
            throw new IllegalStateException("pairing refused: " + outcome.reason());
        }
        return issued;
    }
}

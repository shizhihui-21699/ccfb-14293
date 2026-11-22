package com.bank.atmsecure.link;

import com.bank.atmsecure.dispenser.CashDispenserModule;
import com.bank.atmsecure.model.ModuleId;
import com.bank.atmsecure.model.TerminalId;
import com.bank.atmsecure.wire.HelloAck;

/**
 * Orchestrates one terminal↔dispenser pair over a {@link SimLink}, exactly as the two boxes would be
 * cabled. Tests talk to the terminal and dispenser only through this; they never reach into the
 * module's internals except via the documented simulation hooks.
 */
public final class Simulator implements AutoCloseable {
    private final SimLink link;
    private final CashDispenserModule module;
    private final DispenserEndpoint dispenser;
    private final TerminalEndpoint terminal;

    public Simulator(ModuleId moduleId, CashDispenserModule module, TerminalId terminalId,
            com.bank.atmsecure.auth.ModuleCertificate cert, java.security.PublicKey manufacturingKey,
            java.util.function.Consumer<String> trace) {
        this.link = new SimLink(trace);
        this.module = module;
        this.dispenser = new DispenserEndpoint(module, link, trace);
        this.terminal = new TerminalEndpoint(terminalId, link, manufacturingKey,
                "atm-business/1.0", trace);
    }

    public SimLink link() {
        return link;
    }

    public DispenserEndpoint dispenser() {
        return dispenser;
    }

    public TerminalEndpoint terminal() {
        return terminal;
    }

    public CashDispenserModule module() {
        return module;
    }

    /** The side the terminal endpoint needs: performs connect / challenge / process. */
    public DispenserSide dispenserSide() {
        return new DispenserSide();
    }

    @Override
    public void close() {
        // No resources; present for try-with-resources symmetry.
    }

    /** Adapter handed to the terminal so request/response wiring stays in one place. */
    public final class DispenserSide {
        public boolean connect(TerminalEndpoint t) {
            byte[] hello = t.hello();
            byte[] ackBytes;
            try {
                ackBytes = dispenser.onHello(hello);
            } catch (RuntimeException e) {
                return false;
            }
            try {
                t.acceptHelloAck(ackBytes, t.dispenserCert() != null
                        ? t.dispenserCert()
                        : module.certificate());
                return true;
            } catch (RuntimeException e) {
                return false;
            }
        }

        public byte[] challenge() {
            return module.challenge();
        }

        public byte[] process(byte[] requestFrame) {
            return dispenser.process(requestFrame);
        }

        public HelloAck moduleInfo() {
            return dispenser.lastAck();
        }
    }
}

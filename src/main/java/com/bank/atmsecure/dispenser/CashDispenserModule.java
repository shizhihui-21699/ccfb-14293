package com.bank.atmsecure.dispenser;

import com.bank.atmsecure.auth.DispenseReceipt;
import com.bank.atmsecure.auth.HostAuthorization;
import com.bank.atmsecure.auth.ModuleCertificate;
import com.bank.atmsecure.auth.OfflineEnvelope;
import com.bank.atmsecure.auth.PairingGrant;
import com.bank.atmsecure.crypto.Canonical;
import com.bank.atmsecure.crypto.CryptoException;
import com.bank.atmsecure.crypto.Hex;
import com.bank.atmsecure.model.CashPlan;
import com.bank.atmsecure.model.Money;
import com.bank.atmsecure.model.ModuleId;
import com.bank.atmsecure.model.Protocol;
import com.bank.atmsecure.model.TerminalId;
import com.bank.atmsecure.model.TxId;
import com.bank.atmsecure.security.AuditChain;
import com.bank.atmsecure.security.NvramStore;
import com.bank.atmsecure.security.OtpRegion;
import com.bank.atmsecure.security.RollbackProtectedCounter;
import com.bank.atmsecure.security.SimClock;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * The cash-dispenser controller: the trust boundary that actually moves money.
 *
 * <p>Holds its own private key (never exported) and pins the host's <em>public</em> authorisation key
 * plus service/manufacturing public keys in OTP at provisioning. It therefore needs no secret from
 * the terminal, which is what makes a stolen or cloned terminal harmless.
 *
 * <h2>Online dispense — every check before a note moves</h2>
 * <ol>
 *   <li>Serviceable: not tampered, not locked, within the verify/commit budgets.</li>
 *   <li>Request carries a {@link HostAuthorization} whose signature verifies under the pinned key.</li>
 *   <li>Minted for this module, this paired terminal, this pairing epoch.</li>
 *   <li>Within validity (bounded clock skew); module clock not behind its monotonic floor.</li>
 *   <li>Signed nonce == the one-time challenge this module issued for the current session, unused.</li>
 *   <li>Signed channel binding == this session's.</li>
 *   <li>Amount == signed plan total; cassettes can fulfil the exact plan.</li>
 *   <li>Sequence strictly ahead of the OTP-anchored high-water mark, within the jump bound.</li>
 * </ol>
 * Only if all pass does it consume the nonce, advance the OTP-anchored sequence, drive transport, and
 * emit the signed receipt.
 *
 * <h2>Offline dispense — bounded by OTP-anchored cumulative spend</h2>
 * The module keeps a lifetime cumulative offline <em>spend</em> (cents) and <em>transaction count</em>,
 * both OTP-anchored and forward-only (see {@link RollbackProtectedCounter}). The host-signed envelope
 * carries absolute ceilings on those same cumulative quantities. A dispense passes only if
 * {@code cumulativeSpend + amount <= spendCap} and {@code cumulativeCount + 1 <= txCountCap}. Rolling
 * NVRAM back cannot refill budget because the OTP floor keeps the cumulative spend in place, and an
 * absolute cap cannot be exceeded by replaying envelopes.
 */
public final class CashDispenserModule {

    // NVRAM mirror keys (untrusted, revalidated against OTP at boot).
    private static final String K_EPOCH = "pair.epoch";
    private static final String K_TERMINAL = "pair.terminal";
    private static final String K_SEQ_HW = "dispense.seq.highwater";
    private static final String K_RECEIPT_SEQ = "receipt.seq";
    private static final String K_RECEIPT_HASH = "receipt.hash";
    private static final String K_OFFLINE_SPENT = "offline.spent.cum";
    private static final String K_OFFLINE_COUNT = "offline.count.cum";
    private static final String K_OFFLINE_ENV = "offline.envelope.fp";
    private static final String K_OFFLINE_ENV_BODY = "offline.envelope.body";
    private static final String K_AUDIT_TIP = "audit.tip";
    private static final String K_AUDIT_INDEX = "audit.index";
    private static final String K_CASSETTES = "cassettes";
    private static final String K_GRANT_PREFIX = "pair.grant.";
    private static final String K_BURNED_PREFIX = "offline.burned.";

    private final ModuleId moduleId;
    private final KeyPair moduleKey;
    private final ModuleCertificate certificate;
    private final PublicKey hostAuthorizationKey;
    private final PublicKey serviceAuthorityKey;
    private final SimClock clock;

    private final NvramStore nvram;
    private final OtpRegion seqOtp;
    private final OtpRegion offlineSpendOtp;
    private final OtpRegion offlineCountOtp;
    private final OtpRegion epochOtp;
    private final RollbackProtectedCounter seqCounter;
    private final RollbackProtectedCounter offlineSpendCounter;
    private final RollbackProtectedCounter offlineCountCounter;
    private final AuditChain audit;
    private final CassetteBank cassettes;

    private TerminalId pairedTerminal;
    private int keyEpoch;
    private long seqHighWater;
    private long receiptSeq;
    private byte[] lastReceiptHash;

    private byte[] activeOfflineEnvelopeFp;
    private OfflineEnvelope activeOfflineEnvelope;

    // Per-session challenge.
    private long currentSessionId = Long.MIN_VALUE;
    private byte[] currentChannelBinding;
    private byte[] pendingNonce;
    private long pendingNonceIssuedAt;

    private final TokenBucket verifyBudget;
    private final TokenBucket helloBudget;
    private int consecutiveAuthFailures;
    private long nvramCommitsThisHour;
    private long commitWindowStart;

    private boolean serviceMode;
    private boolean rngStuck;
    private byte[] lastRngDraw;
    private boolean booted;
    private String tamperReason;

    public CashDispenserModule(ModuleId moduleId, KeyPair moduleKey, ModuleCertificate certificate,
            PublicKey hostAuthorizationKey, PublicKey serviceAuthorityKey, SimClock clock) {
        this.moduleId = moduleId;
        this.moduleKey = moduleKey;
        this.certificate = certificate;
        this.hostAuthorizationKey = hostAuthorizationKey;
        this.serviceAuthorityKey = serviceAuthorityKey;
        this.clock = clock;
        this.nvram = new NvramStore();
        // OTP sizing: sequence anchor burned per successful dispense; offline spend/count burned per
        // offline dispense (rare). Capacities are chosen to outlast the service life at those rates.
        this.seqOtp = new OtpRegion("seq-highwater", 65_536);
        this.offlineSpendOtp = new OtpRegion("offline-spend", 4_096);
        this.offlineCountOtp = new OtpRegion("offline-count", 4_096);
        this.epochOtp = new OtpRegion("pairing-epoch", 256);
        this.seqCounter = new RollbackProtectedCounter("seq-highwater", seqOtp);
        this.offlineSpendCounter = new RollbackProtectedCounter("offline-spend", offlineSpendOtp);
        this.offlineCountCounter = new RollbackProtectedCounter("offline-count", offlineCountOtp);
        this.audit = new AuditChain(256);
        this.cassettes = new CassetteBank();
        this.verifyBudget = new TokenBucket(ResourceLimits.MAX_VERIFY_PER_SECOND, 1000, clock);
        this.helloBudget = new TokenBucket(ResourceLimits.MAX_HELLO_PER_SECOND, 1000, clock);
        this.commitWindowStart = clock.millis();
        this.lastReceiptHash = new byte[Protocol.HASH_BYTES];
    }

    /** Factory provisioning: verify the manufacturing certificate and seed the epoch anchor. */
    public void provisionAtFactory() {
        if (!certificate.verify(serviceAuthorityKey)) {
            audit.append(clock.millis(), AuditChain.Kind.HEALTH_FAILURE,
                    "certificate does not verify at manufacture");
        }
        if (!Arrays.equals(certificate.modulePublicKey(),
                com.bank.atmsecure.crypto.Ed25519.rawPublic(moduleKey.getPublic()))) {
            audit.append(clock.millis(), AuditChain.Kind.HEALTH_FAILURE,
                    "certificate public key does not match module key");
        }
        epochOtp.seed(0);
    }

    public ModuleId moduleId() {
        return moduleId;
    }

    public ModuleCertificate certificate() {
        return certificate;
    }

    public byte[] publicKeyRaw() {
        return com.bank.atmsecure.crypto.Ed25519.rawPublic(moduleKey.getPublic());
    }

    public boolean isPaired() {
        return pairedTerminal != null;
    }

    public TerminalId pairedTerminal() {
        return pairedTerminal;
    }

    public int keyEpoch() {
        return keyEpoch;
    }

    public long seqHighWater() {
        return seqHighWater;
    }

    public boolean isLocked() {
        if (tamperReason != null || rngStuck) {
            return true;
        }
        if (offlineSpendCounter.isTampered() || offlineCountCounter.isTampered()) {
            return true;
        }
        return consecutiveAuthFailures >= ResourceLimits.MAX_CONSECUTIVE_AUTH_FAILURES;
    }

    public String lockReason() {
        if (tamperReason != null) {
            return tamperReason;
        }
        if (rngStuck) {
            return "RNG health check failed";
        }
        if (offlineSpendCounter.isTampered()) {
            return offlineSpendCounter.tamperReason();
        }
        if (offlineCountCounter.isTampered()) {
            return offlineCountCounter.tamperReason();
        }
        if (consecutiveAuthFailures >= ResourceLimits.MAX_CONSECUTIVE_AUTH_FAILURES) {
            return "too many authorisation failures; service required";
        }
        return null;
    }

    public CassetteBank cassettes() {
        return cassettes;
    }

    public AuditChain audit() {
        return audit;
    }

    public NvramStore nvram() {
        return nvram;
    }

    public long offlineSpentCumulative() {
        return offlineSpendCounter.peek();
    }

    public long offlineCountCumulative() {
        return offlineCountCounter.peek();
    }

    public long receiptSeq() {
        return receiptSeq;
    }

    public byte[] lastReceiptHash() {
        return lastReceiptHash.clone();
    }

    // ---------------------------------------------------------------------------------------------
    // Session / handshake surface
    // ---------------------------------------------------------------------------------------------

    public boolean admitHello() {
        if (isLocked()) {
            return false;
        }
        return helloBudget.tryConsume(clock);
    }

    /** Opens a session and draws its one-time challenge. Fails closed if the RNG is unhealthy. */
    public void openSession(long sessionId, byte[] channelBinding) {
        currentSessionId = sessionId;
        currentChannelBinding = Canonical.copy(channelBinding);
        byte[] nonce = new byte[Protocol.NONCE_BYTES];
        if (!drawRandom(nonce)) {
            pendingNonce = null;
            failClosed("RNG draw failed at session open");
            return;
        }
        pendingNonce = nonce;
        pendingNonceIssuedAt = clock.millis();
        audit.append(clock.millis(), AuditChain.Kind.SESSION_OPENED,
                "session=" + Long.toUnsignedString(sessionId));
        audit.append(clock.millis(), AuditChain.Kind.NONCE_ISSUED, Hex.encode(nonce, 8));
    }

    public byte[] challenge() {
        if (pendingNonce == null) {
            throw new IllegalStateException("no challenge available (session not open or RNG failed)");
        }
        return pendingNonce.clone();
    }

    public byte[] currentChannelBinding() {
        return currentChannelBinding == null ? null : currentChannelBinding.clone();
    }

    // ---------------------------------------------------------------------------------------------
    // Pairing
    // ---------------------------------------------------------------------------------------------

    /**
     * Binds this module to a terminal at a new epoch. Three independent gates: host-signed grant for
     * this exact module/terminal/epoch; physical service jumper closed; grant not used before and
     * within validity. Success advances the OTP-anchored epoch and clears all spend state.
     */
    public synchronized PairingOutcome pair(PairingGrant grant, boolean serviceJumperClosed) {
        if (!serviceJumperClosed) {
            audit.append(clock.millis(), AuditChain.Kind.PAIRING, "refused: service jumper open");
            return PairingOutcome.refused("service jumper must be closed for pairing");
        }
        if (!grant.verifySignature(serviceAuthorityKey)) {
            audit.append(clock.millis(), AuditChain.Kind.PAIRING, "refused: bad grant signature");
            return PairingOutcome.refused("pairing grant signature invalid");
        }
        if (!grant.moduleId().equals(moduleId)) {
            audit.append(clock.millis(), AuditChain.Kind.PAIRING,
                    "refused: grant for other module " + grant.moduleId());
            return PairingOutcome.refused("pairing grant names a different module");
        }
        long now = clock.millis();
        if (now < grant.issuedAtMillis() - Protocol.CLOCK_SKEW_MILLIS
                || now > grant.expiresAtMillis() + Protocol.CLOCK_SKEW_MILLIS) {
            audit.append(clock.millis(), AuditChain.Kind.PAIRING, "refused: grant outside validity");
            return PairingOutcome.refused("pairing grant expired or not yet valid");
        }
        if (nvram.get(K_GRANT_PREFIX + grant.grantId()) != null) {
            audit.append(clock.millis(), AuditChain.Kind.PAIRING, "refused: grant already used");
            return PairingOutcome.refused("pairing grant already used");
        }
        if (grant.newKeyEpoch() <= epochOtp.floor()) {
            audit.append(clock.millis(), AuditChain.Kind.PAIRING,
                    "refused: non-advancing epoch " + grant.newKeyEpoch() + " <= "
                            + epochOtp.floor());
            return PairingOutcome.refused("pairing epoch must advance");
        }

        keyEpoch = grant.newKeyEpoch();
        epochOtp.tryBurn(keyEpoch);
        pairedTerminal = grant.terminalId();
        // The dispense-sequence high-water is NOT reset: the host keeps allocating sequence numbers
        // monotonically regardless of epoch, so resetting it here would let a fresh authorisation be
        // refused, or (worse) an old one at a higher sequence be replayed. Re-pairing only advances
        // the epoch, which invalidates old authorisations by epoch, not by sequence.
        activeOfflineEnvelope = null;
        activeOfflineEnvelopeFp = null;
        audit.append(now, AuditChain.Kind.PAIRING, "paired to " + grant.terminalId()
                + " epoch=" + keyEpoch + " workOrder=" + grant.workOrderId());
        persist(Map.of(K_GRANT_PREFIX + grant.grantId(), RollbackProtectedCounter.longBytes(now)));
        return PairingOutcome.accepted(pairedTerminal, keyEpoch);
    }

    public void setServiceMode(boolean on) {
        this.serviceMode = on;
        audit.append(clock.millis(), AuditChain.Kind.PAIRING, "service mode " + (on ? "on" : "off"));
    }

    public boolean serviceMode() {
        return serviceMode;
    }

    /** Loads an offline envelope after validating its binding and single-use status. */
    public synchronized boolean loadOfflineEnvelope(OfflineEnvelope env) {
        if (isLocked()) {
            audit.append(clock.millis(), AuditChain.Kind.ENVELOPE_REFUSED, "module locked");
            return false;
        }
        String why = envelopeDefect(env);
        if (why != null) {
            audit.append(clock.millis(), AuditChain.Kind.ENVELOPE_REFUSED, why);
            return false;
        }
        byte[] fp = env.fingerprint();
        String burnedKey = K_BURNED_PREFIX + Hex.encode(fp, 8);
        if (nvram.get(burnedKey) != null) {
            audit.append(clock.millis(), AuditChain.Kind.ENVELOPE_REFUSED, "envelope already used");
            return false;
        }
        if (activeOfflineEnvelopeFp != null && Arrays.equals(activeOfflineEnvelopeFp, fp)) {
            // Already the active envelope. Re-loading it must not reset anything (the absolute caps
            // would prevent extra spend anyway, but refusing keeps the state machine simple).
            audit.append(clock.millis(), AuditChain.Kind.ENVELOPE_REFUSED, "envelope already active");
            return false;
        }
        // A different, fresh envelope replaces any previous one; burn the old id so it cannot be
        // reloaded later to reset its caps.
        Map<String, byte[]> extra = new HashMap<>();
        if (activeOfflineEnvelopeFp != null) {
            extra.put(K_BURNED_PREFIX + Hex.encode(activeOfflineEnvelopeFp, 8),
                    RollbackProtectedCounter.longBytes(clock.millis()));
        }
        activeOfflineEnvelope = env;
        activeOfflineEnvelopeFp = fp;
        audit.append(clock.millis(), AuditChain.Kind.ENVELOPE_LOADED, env.envelopeId()
                + " spendCap=" + Money.ofCents(env.spendCapCents()) + " countCap="
                + env.txCountCap());
        extra.put(K_OFFLINE_ENV, fp);
        // Persist the envelope body itself so offline mode survives a power cycle without the
        // terminal having to re-present (and the module re-accept) an envelope it already loaded.
        extra.put(K_OFFLINE_ENV_BODY, env.encode());
        persist(extra);
        return true;
    }

    private String envelopeDefect(OfflineEnvelope env) {
        if (!env.verifySignature(hostAuthorizationKey)) {
            return "bad envelope signature " + env.envelopeId();
        }
        if (!env.moduleId().equals(moduleId)) {
            return "envelope names another module";
        }
        if (env.keyEpoch() != keyEpoch) {
            return "envelope epoch " + env.keyEpoch() + " != current " + keyEpoch;
        }
        if (pairedTerminal == null || !env.terminalId().equals(pairedTerminal)) {
            return "envelope for another terminal";
        }
        return null;
    }

    // ---------------------------------------------------------------------------------------------
    // Dispense
    // ---------------------------------------------------------------------------------------------

    /** Single entry point. Performs every check, then moves cash and mints the receipt. */
    public synchronized DispenseResult dispense(DispenseRequest request) {
        long now = clock.millis();
        if (isLocked()) {
            audit.append(now, AuditChain.Kind.DISPENSE_REFUSED, "locked: " + lockReason());
            return DispenseResult.refused(DispenseStatus.MODULE_LOCKED, "module locked");
        }
        if (request == null) {
            return DispenseResult.refused(DispenseStatus.BAD_REQUEST, "null");
        }
        if (!verifyBudget.tryConsume(clock)) {
            audit.append(now, AuditChain.Kind.THROTTLED, "verify budget exhausted");
            return DispenseResult.refused(DispenseStatus.THROTTLED, "slow down");
        }
        try {
            return request instanceof DispenseRequest.Online online
                    ? dispenseOnline(online, now)
                    : dispenseOffline((DispenseRequest.Offline) request, now);
        } catch (CryptoException e) {
            return authFail(AuditChain.Kind.AUTH_REJECTED, "crypto failure: " + e.getMessage(),
                    "invalid request");
        } catch (RuntimeException e) {
            return authFail(AuditChain.Kind.AUTH_REJECTED, "malformed request: " + e.getMessage(),
                    "invalid request");
        }
    }

    private DispenseResult dispenseOnline(DispenseRequest.Online req, long now) {
        HostAuthorization a = req.authorization();
        if (!a.moduleId().equals(moduleId)) {
            return authFail(AuditChain.Kind.AUTH_REJECTED, "authorization for other module "
                    + a.moduleId(), "wrong module");
        }
        if (pairedTerminal == null) {
            return authFail(AuditChain.Kind.AUTH_REJECTED, "module not paired", "not paired");
        }
        if (!a.terminalId().equals(pairedTerminal)) {
            return authFail(AuditChain.Kind.AUTH_REJECTED, "authorization for terminal "
                    + a.terminalId() + " but paired to " + pairedTerminal, "wrong terminal");
        }
        if (a.keyEpoch() != keyEpoch) {
            return authFail(AuditChain.Kind.AUTH_REJECTED, "epoch mismatch " + a.keyEpoch()
                    + " vs " + keyEpoch, "stale pairing");
        }
        if (!a.verifySignature(hostAuthorizationKey)) {
            return authFail(AuditChain.Kind.AUTH_REJECTED, "host signature invalid for " + a.txId(),
                    "authorization rejected");
        }
        if (now > a.expiresAtMillis() + Protocol.CLOCK_SKEW_MILLIS) {
            return authFail(AuditChain.Kind.AUTH_REJECTED, "expired at " + a.expiresAtMillis()
                    + " now " + now, "expired");
        }
        if (now + Protocol.CLOCK_SKEW_MILLIS < a.issuedAtMillis()) {
            return authFail(AuditChain.Kind.AUTH_REJECTED, "not yet valid (issued "
                    + a.issuedAtMillis() + ")", "authorization rejected");
        }
        if (!Arrays.equals(a.channelBinding(), currentChannelBinding)) {
            return authFail(AuditChain.Kind.AUTH_REJECTED, "channel binding mismatch",
                    "authorization rejected");
        }
        if (pendingNonce == null || !Arrays.equals(a.nonce(), pendingNonce)) {
            return authFail(AuditChain.Kind.NONCE_REJECTED, "nonce is not the current challenge",
                    "stale challenge");
        }
        if (now - pendingNonceIssuedAt > ResourceLimits.NONCE_LIFETIME_MILLIS) {
            pendingNonce = null;
            return authFail(AuditChain.Kind.NONCE_REJECTED, "challenge expired", "stale challenge");
        }
        if (a.seq() <= seqHighWater) {
            return authFail(AuditChain.Kind.SEQ_REJECTED, "seq " + a.seq() + " <= highwater "
                    + seqHighWater, "stale sequence");
        }
        if (a.seq() - seqHighWater > Protocol.MAX_SEQ_JUMP) {
            return authFail(AuditChain.Kind.SEQ_REJECTED, "seq jump too large " + a.seq(),
                    "stale sequence");
        }
        if (a.amountCents() != a.plan().totalCents()) {
            return authFail(AuditChain.Kind.AUTH_REJECTED, "amount/plan mismatch",
                    "authorization rejected");
        }
        if (!cassettes.canFulfil(a.plan())) {
            audit.append(now, AuditChain.Kind.DISPENSE_REFUSED, "cannot fulfil " + a.plan()
                    + " cassettes=" + cassettes.describe());
            return DispenseResult.refused(DispenseStatus.INSUFFICIENT_CASH, "insufficient cash");
        }
        if (!reserveNvramCommit(now)) {
            return DispenseResult.refused(DispenseStatus.THROTTLED, "maintenance window");
        }

        // ---- Committed: consume nonce + sequence, then move cash and mint the receipt. ----
        // Crash-safe ordering: (1) persist the advanced state to NVRAM, (2) burn the OTP anchor,
        // (3) move cash. A power cut before (2) leaves NVRAM >= OTP floor, so boot does not mistake it
        // for a rollback; a cut after (2) may refuse this later spend but can never grant cash. See
        // RollbackProtectedCounter.incrementBy for the full argument.
        pendingNonce = null;
        long nextSeq = a.seq();
        long prevSeq = seqCounter.peek();
        seqHighWater = nextSeq;
        receiptSeq += 1;
        DispenseReceipt receipt = DispenseReceipt.builder()
                .moduleId(moduleId)
                .terminalId(pairedTerminal)
                .txId(a.txId())
                .offline(false)
                .amountCents(a.amountCents())
                .plan(a.plan())
                .authorizedSeq(a.seq())
                .moduleSeq(receiptSeq)
                .prevReceiptHash(lastReceiptHash)
                .cardInsertedAtMillis(now)
                .completedAtMillis(now)
                .authorizationDigest(a.digest())
                .build()
                .signedBy(moduleKey.getPrivate());
        byte[] nextReceiptHash = receipt.hash();
        lastReceiptHash = nextReceiptHash;
        try {
            persist(Map.of()); // (1) mirror catches up to the new sequence and receipt
            seqCounter.incrementBy(nextSeq - prevSeq); // (2) burn the OTP anchor
        } catch (CryptoException e) {
            failClosed("cannot anchor sequence: " + e.getMessage());
            return DispenseResult.refused(DispenseStatus.MODULE_LOCKED, "module locked");
        }
        cassettes.remove(a.plan()); // (3) money moves only after the anchor is durable
        consecutiveAuthFailures = 0;
        audit.append(now, AuditChain.Kind.DISPENSE_OK, a.txId() + " "
                + Money.ofCents(a.amountCents()) + " " + a.plan() + " seq=" + a.seq()
                + " receipt=" + receiptSeq);
        return DispenseResult.ok(receipt);
    }

    private DispenseResult dispenseOffline(DispenseRequest.Offline req, long now) {
        OfflineEnvelope env = req.envelope();
        CashPlan plan = req.plan();
        if (activeOfflineEnvelopeFp == null || activeOfflineEnvelope == null
                || !Arrays.equals(activeOfflineEnvelopeFp, env.fingerprint())) {
            return authFail(AuditChain.Kind.ENVELOPE_REFUSED, "envelope not loaded",
                    "offline refused");
        }
        if (!Arrays.equals(env.encode(), activeOfflineEnvelope.encode())) {
            return authFail(AuditChain.Kind.ENVELOPE_REFUSED, "envelope differs from loaded one",
                    "offline refused");
        }
        if (now > env.expiresAtMillis() + Protocol.CLOCK_SKEW_MILLIS) {
            return authFail(AuditChain.Kind.ENVELOPE_REFUSED, "envelope expired", "offline refused");
        }
        long amountCents = plan.totalCents();
        if (amountCents > env.perTxMax().cents()) {
            return authFail(AuditChain.Kind.ENVELOPE_REFUSED, "amount "
                    + Money.ofCents(amountCents) + " exceeds per-tx cap " + env.perTxMax(),
                    "offline limit");
        }
        long spent = offlineSpendCounter.peek();
        long count = offlineCountCounter.peek();
        if (spent + amountCents > env.spendCapCents()) {
            return authFail(AuditChain.Kind.ENVELOPE_REFUSED, "would exceed spend cap: "
                    + Money.ofCents(spent) + "+" + Money.ofCents(amountCents) + " > "
                    + Money.ofCents(env.spendCapCents()), "offline limit");
        }
        if (count + 1 > env.txCountCap()) {
            return authFail(AuditChain.Kind.ENVELOPE_REFUSED, "would exceed count cap: " + count,
                    "offline limit");
        }
        long seqCandidate = env.seqStart() + (count + 1);
        if (seqCandidate > env.seqEnd()) {
            return authFail(AuditChain.Kind.ENVELOPE_REFUSED, "envelope sequence window exhausted",
                    "offline limit");
        }
        if (!cassettes.canFulfil(plan)) {
            return DispenseResult.refused(DispenseStatus.INSUFFICIENT_CASH, "insufficient cash");
        }
        if (!reserveNvramCommit(now)) {
            return DispenseResult.refused(DispenseStatus.THROTTLED, "maintenance window");
        }

        // Commit with the same crash-safe ordering as the online path: persist NVRAM, burn the OTP
        // anchors, then move cash. The cumulative counters are advanced in the persisted mirror first
        // so a mid-dispense power cut never leaves NVRAM below the OTP floor.
        receiptSeq += 1;
        TxId tx = new TxId("OFF-" + moduleId.value() + "-" + receiptSeq);
        DispenseReceipt receipt = DispenseReceipt.builder()
                .moduleId(moduleId)
                .terminalId(pairedTerminal)
                .txId(tx)
                .offline(true)
                .offlineEnvelopeId(env.envelopeId())
                .amountCents(amountCents)
                .plan(plan)
                .authorizedSeq(seqCandidate)
                .moduleSeq(receiptSeq)
                .prevReceiptHash(lastReceiptHash)
                .cardInsertedAtMillis(now)
                .completedAtMillis(now)
                .authorizationDigest(env.fingerprint())
                .build()
                .signedBy(moduleKey.getPrivate());
        lastReceiptHash = receipt.hash();
        // Advance the counters' values (so baseState() mirrors the new totals), persisting before the
        // OTP burn and the cash movement.
        offlineCountCounter.setValue(count + 1);
        offlineSpendCounter.setValue(spent + amountCents);
        try {
            persist(Map.of());
            offlineCountCounter.anchor(); // burn OTP anchor for the count
            offlineSpendCounter.anchor(); // burn OTP anchor for the cumulative spend
        } catch (CryptoException e) {
            failClosed("cannot anchor offline spend: " + e.getMessage());
            return DispenseResult.refused(DispenseStatus.MODULE_LOCKED, "module locked");
        }
        cassettes.remove(plan);
        consecutiveAuthFailures = 0;
        audit.append(now, AuditChain.Kind.DISPENSE_OK, "OFFLINE " + tx + " "
                + Money.ofCents(amountCents) + " " + plan + " cumSpent="
                + Money.ofCents(spent + amountCents) + " cumCount=" + (count + 1));
        return DispenseResult.ok(receipt);
    }

    private DispenseResult authFail(AuditChain.Kind kind, String detail, String wireDetail) {
        consecutiveAuthFailures++;
        audit.append(clock.millis(), kind, detail);
        if (consecutiveAuthFailures >= ResourceLimits.MAX_CONSECUTIVE_AUTH_FAILURES) {
            audit.append(clock.millis(), AuditChain.Kind.TAMPER,
                    "auth failure threshold reached");
        }
        return DispenseResult.refused(DispenseStatus.AUTHORIZATION_REJECTED, wireDetail);
    }

    private boolean reserveNvramCommit(long now) {
        if (now - commitWindowStart >= 3_600_000L) {
            commitWindowStart = now;
            nvramCommitsThisHour = 0;
        }
        if (nvramCommitsThisHour >= ResourceLimits.MAX_NVRAM_COMMITS_PER_HOUR) {
            audit.append(now, AuditChain.Kind.THROTTLED, "NVRAM commit budget exhausted");
            return false;
        }
        nvramCommitsThisHour++;
        return true;
    }

    private void failClosed(String reason) {
        if (tamperReason == null) {
            tamperReason = reason;
        }
        audit.append(clock.millis(), AuditChain.Kind.TAMPER, reason);
    }

    // ---------------------------------------------------------------------------------------------
    // Persistence
    // ---------------------------------------------------------------------------------------------

    private Map<String, byte[]> baseState() {
        Map<String, byte[]> m = new HashMap<>();
        m.put(K_EPOCH, RollbackProtectedCounter.longBytes(keyEpoch));
        m.put(K_TERMINAL, (pairedTerminal == null ? "" : pairedTerminal.value())
                .getBytes(java.nio.charset.StandardCharsets.UTF_8));
        m.put(K_SEQ_HW, RollbackProtectedCounter.longBytes(seqHighWater));
        m.put(K_RECEIPT_SEQ, RollbackProtectedCounter.longBytes(receiptSeq));
        m.put(K_RECEIPT_HASH, lastReceiptHash);
        m.put(K_OFFLINE_SPENT, RollbackProtectedCounter.longBytes(offlineSpendCounter.peek()));
        m.put(K_OFFLINE_COUNT, RollbackProtectedCounter.longBytes(offlineCountCounter.peek()));
        m.put(K_OFFLINE_ENV, activeOfflineEnvelopeFp == null ? new byte[0] : activeOfflineEnvelopeFp);
        m.put(K_OFFLINE_ENV_BODY, activeOfflineEnvelope == null ? new byte[0]
                : activeOfflineEnvelope.encode());
        m.put(K_AUDIT_TIP, audit.tip());
        m.put(K_AUDIT_INDEX, RollbackProtectedCounter.longBytes(audit.nextIndex()));
        m.put(K_CASSETTES, cassettes.encodeState());
        return m;
    }

    private void persist(Map<String, byte[]> extra) {
        Map<String, byte[]> state = new HashMap<>(baseState());
        state.putAll(extra);
        nvram.commit(state);
    }

    /**
     * Restores volatile state from NVRAM (untrusted) and cross-checks it against OTP. Any rollback of
     * the OTP-anchored quantities latches tamper and the module refuses to operate.
     */
    public synchronized void boot() {
        // Restore the audit chain so it remains continuous across power cycles (the tip is mirrored
        // in NVRAM; a rollback of that mirror is caught against the OTP-anchored receipt sequence at
        // reconciliation rather than here, since the audit log is evidence, not a spend control).
        audit.restore(nvram.get(K_AUDIT_TIP), nvram.getLong(K_AUDIT_INDEX, 0L));
        byte[] epoch = nvram.get(K_EPOCH);
        if (epoch != null) {
            int storedEpoch = (int) RollbackProtectedCounter.bytesToLong(epoch);
            if (storedEpoch < epochOtp.floor()) {
                failClosed("pairing epoch rolled back: stored " + storedEpoch + " < OTP "
                        + epochOtp.floor());
            } else {
                keyEpoch = storedEpoch;
            }
        } else {
            keyEpoch = (int) epochOtp.floor();
        }
        byte[] term = nvram.get(K_TERMINAL);
        if (term != null && term.length > 0) {
            try {
                pairedTerminal = new TerminalId(
                        new String(term, java.nio.charset.StandardCharsets.UTF_8));
            } catch (IllegalArgumentException e) {
                failClosed("corrupt terminal id in NVRAM");
            }
        }
        try {
            seqHighWater = seqCounter.bootFrom(nvram.getLong(K_SEQ_HW, seqCounter.peek()));
        } catch (CryptoException e) {
            failClosed("sequence rollback: " + e.getMessage());
            seqHighWater = seqCounter.peek();
        }
        receiptSeq = nvram.getLong(K_RECEIPT_SEQ, receiptSeq);
        byte[] rh = nvram.get(K_RECEIPT_HASH);
        if (rh != null && rh.length == Protocol.HASH_BYTES) {
            lastReceiptHash = rh;
        }
        try {
            offlineSpendCounter.bootFrom(
                    nvram.getLong(K_OFFLINE_SPENT, offlineSpendCounter.peek()));
            offlineCountCounter.bootFrom(
                    nvram.getLong(K_OFFLINE_COUNT, offlineCountCounter.peek()));
        } catch (CryptoException e) {
            failClosed("offline spend rollback: " + e.getMessage());
        }
        byte[] envFp = nvram.get(K_OFFLINE_ENV);
        activeOfflineEnvelopeFp = envFp == null || envFp.length == 0 ? null : envFp;
        // Restore the envelope body so offline mode continues across a reboot. Its signature and
        // binding are re-checked here; a tampered body is discarded rather than trusted.
        activeOfflineEnvelope = null;
        byte[] envBody = nvram.get(K_OFFLINE_ENV_BODY);
        if (envBody != null && envBody.length > 0) {
            try {
                OfflineEnvelope restored = OfflineEnvelope.decode(envBody);
                if (envelopeDefect(restored) == null
                        && activeOfflineEnvelopeFp != null
                        && Arrays.equals(activeOfflineEnvelopeFp, restored.fingerprint())) {
                    activeOfflineEnvelope = restored;
                } else {
                    failClosed("stored offline envelope failed revalidation at boot");
                }
            } catch (RuntimeException e) {
                failClosed("corrupt offline envelope in NVRAM");
            }
        }
        byte[] cs = nvram.get(K_CASSETTES);
        if (cs != null) {
            try {
                CassetteBank restored = CassetteBank.decodeState(cs);
                for (com.bank.atmsecure.model.Denomination d
                        : com.bank.atmsecure.model.Denomination.values()) {
                    cassettes.load(d, restored.countOf(d));
                }
            } catch (RuntimeException e) {
                failClosed("corrupt cassette state in NVRAM");
            }
        }
        booted = true;
        audit.append(clock.millis(), AuditChain.Kind.SESSION_OPENED, "boot");
    }

    public boolean booted() {
        return booted;
    }

    // ---------------------------------------------------------------------------------------------
    // Attack-simulation hooks
    // ---------------------------------------------------------------------------------------------

    /** Chip-off attack: replace NVRAM with a captured image. Rollback is caught at the next boot. */
    public void restoreNvramImage(NvramStore.NvramImage image) {
        nvram.restoreImage(image);
    }

    public NvramStore.NvramImage captureNvram() {
        return nvram.captureImage();
    }

    public void injectTornWrite() {
        nvram.simulateTornWrite();
    }

    /** Fault injection on the entropy source: challenges would become predictable, so we lock. */
    public void injectStuckRng() {
        rngStuck = true;
        audit.append(clock.millis(), AuditChain.Kind.HEALTH_FAILURE, "RNG forced stuck");
    }

    public void simulatePhysicalTheft(CashPlan plan) {
        cassettes.remove(plan);
    }

    private boolean drawRandom(byte[] out) {
        if (rngStuck) {
            return false;
        }
        new java.security.SecureRandom().nextBytes(out);
        if (lastRngDraw != null && Arrays.equals(lastRngDraw, out)) {
            rngStuck = true;
            return false;
        }
        lastRngDraw = out.clone();
        return true;
    }

    public String healthSummary() {
        return "module=" + moduleId + " epoch=" + keyEpoch + " paired=" + pairedTerminal
                + " seqHW=" + seqHighWater + " receipts=" + receiptSeq
                + " offline[cumSpent=" + Money.ofCents(offlineSpendCounter.peek())
                + " cumCount=" + offlineCountCounter.peek() + "] "
                + "cassettes[" + cassettes.describe() + "] " + nvram.digest() + " "
                + audit.describeTip()
                + (isLocked() ? " LOCKED(" + lockReason() + ")" : "");
    }

    /**
     * Signs a handshake transcript with the module's key. The private key never leaves the module;
     * this is the only signing the link layer may ask of it, and the transcript is bound to fresh
     * ephemeral keys so the signature conveys "this certified module is present now" and nothing more.
     */
    public byte[] signHandshakeTranscript(byte[] transcript) {
        return com.bank.atmsecure.crypto.Ed25519.sign(moduleKey.getPrivate(), transcript);
    }


    public record PairingOutcome(boolean accepted, TerminalId terminal, int keyEpoch, String reason) {
        static PairingOutcome accepted(TerminalId t, int epoch) {
            return new PairingOutcome(true, t, epoch, "");
        }

        static PairingOutcome refused(String reason) {
            return new PairingOutcome(false, null, -1, reason);
        }
    }
}

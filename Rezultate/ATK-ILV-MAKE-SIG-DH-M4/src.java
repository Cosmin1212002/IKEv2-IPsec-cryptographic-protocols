package secpro.pkc;

import java.security.KeyPair;

import javax.crypto.SecretKey;

import comm.AppComm;
import crypto.GenSessionKeyBytes;
import crypto.KeyAgrDH;
import misc.Utils;
import secpro.AkeState;
import secpro.CryptoConfig;
import secpro.OwnCrypto;
import secpro.SecProBase;
import secpro.msg.AuthMsg;
import secpro.msg.FailMsg;
import secpro.msg.InitAuthMsg;
import secpro.msg.InitMsg;
import secpro.msg.MsgType;

/**
 *
 * Adversary implementation for interleaving attack (ILV) on
 * MAKE-SIG-PKC-DHE 4-message vulnerable protocol.
 *
 * The adversary impersonates A to B by:
 *  - intercepting InitMsg from A
 *  - substituting own DH public key
 *  - forwarding messages between A and B
 *  - reusing A's signature and certificate to authenticate to B
 *
 */

public class AdvMAkeSigIKEILV extends SecProBase
{
    // Honest parties identities
    private String anaId;
    private String bobId;
    // Attack session identifier (same as Ana's session)
    private byte[] sidAtk;
    // Nonces used in the interleaving attack
    private byte[] nonceA;
    private byte[] nonceB;
    // Bob's DH public key intercepted from InitBA
    private byte[] bobDHPubBytes;
    // Adversary's own ephemeral DH key pair
    private KeyPair advDHKeyPair;

    public AdvMAkeSigIKEILV(AppComm appComm, String locId, byte[] sessionId,
            CryptoConfig commonCrypto, OwnCrypto ownCrypto) throws Exception
    {
        super(appComm, locId, sessionId, commonCrypto, ownCrypto);
    }

    /**
     * Initializes adversary state.
     * No active message is sent; waits for intercepted traffic.
     */
    public void doKeyExch(String locId, String remId) throws Exception
    {
        this.locId = locId;
        this.remId = remId;
        this.state = AkeState.START;
        this.success = false;

        this.anaId = null;
        this.bobId = null;
        this.sidAtk = null;
        this.nonceA = null;
        this.nonceB = null;
        this.bobDHPubBytes = null;
        this.advDHKeyPair = null;

        Utils.trace("[AdvKeyEx: " + this.locId + "] waiting for InitAB...");
    }

    /**
     * Processes intercepted InitMsg.
     *
     * Two roles:
     *  - First InitMsg: from A -> intercepted and modified -> sent to B
     *  - Second InitMsg: from B -> forwarded to A
     */
    public byte[] recvInitMsg(InitMsg msg) throws Exception
    {
        Utils.trace("[AdvKeyEx: " + locId + "] recv InitMsg in state " + state
                + " from " + msg.getSrc() + " to " + msg.getDst());

        switch (state) {
        case START:
            // intercept InitAB (A -> B)
            anaId = msg.getSrc();
            bobId = msg.getDst();
            // Store Bob as the real peer of the adversary session
            remId = bobId;
            // Adversary plays initiator role towards Bob
            initiator = true;
            // Reuse Ana's nonce and session identifier
            nonceA = msg.getNonce();
            sidAtk = msg.getSid();
            // Generate adversary DH key pair
            advDHKeyPair = KeyAgrDH.genDHKeyPair(
                    commonCrypto.getDhName(),
                    commonCrypto.getDhKeyLen()
            );
            // Send forged InitMsg to B with Ana's identity and nonce,
            // but adversary's own DH public key
            InitMsg initToBob = new InitMsg(
                    MsgType.INIT_A,
                    anaId,
                    bobId,
                    sidAtk,
                    nonceA,
                    advDHKeyPair.getPublic().getEncoded(),
                    null,
                    null
            );
            state = AkeState.INIT_SENT;
            Utils.trace("[AdvKeyEx: " + locId + "] send forged InitAB to " + bobId
                    + ", new state " + state);
            appComm.sendInitMsg(initToBob);
            break;

        case INIT_SENT:
            // intercept InitBA (B -> A)
            if (!msg.getSrc().equals(bobId) || !msg.getDst().equals(anaId)) {
                sendFailMsg(msg.getSrc(),
                        "[AdvKeyEx: " + locId + "] Illegal peer in INIT_SENT");
                return null;
            }
            // Store Bob's nonce and DH public key
            nonceB = msg.getNonce();
            bobDHPubBytes = msg.getDHKey();
            // Forward Bob's InitMsg to Ana without modification
            InitMsg initToAna = new InitMsg(
                    MsgType.INIT_B,
                    bobId,
                    anaId,
                    sidAtk,
                    nonceB,
                    bobDHPubBytes,
                    null,
                    null
            );
            state = AkeState.INIT_RCVD;
            Utils.trace("[AdvKeyEx: " + locId + "] relay InitBA to " + anaId
                    + ", new state " + state);
            appComm.sendInitMsg(initToAna);
            break;
        case ESTABLISHED:
            break;
        case FAILED:
            break;
        default:
            sendFailMsg(msg.getSrc(),
                    "[AdvKeyEx: " + locId + "] Illegal state " + state);
        }
        return null;
    }

    /**
     * Processes intercepted AuthMsg.
     *
     * Steps:
     *  - intercept AuthAB -> forward to B
     *  - intercept AuthBA -> derive attack success and abort S1
     */
    public byte[] recvAuthMsg(AuthMsg msg) throws Exception
    {
        Utils.trace("[AdvKeyEx: " + locId + "] recv AuthMsg in state " + state
                + " from " + msg.getSrc() + " to " + msg.getDst());

        switch (state) {
        case INIT_RCVD:
            // intercept AuthAB (A -> B)
            if (!msg.getSrc().equals(anaId) || !msg.getDst().equals(bobId)) {
                sendFailMsg(msg.getSrc(),
                        "[AdvKeyEx: " + locId + "] Illegal peer in INIT_RCVD");
                return null;
            }
            // Forward Ana's authenticator and certificate to Bob unchanged
            AuthMsg authToBob = new AuthMsg(
                    MsgType.AUTH_A,
                    anaId,
                    bobId,
                    sidAtk,
                    msg.getAuth(),
                    msg.getCert(),
                    null
            );
            state = AkeState.AUTH_SENT;
            Utils.trace("[AdvKeyEx: " + locId + "] relay AuthAB to " + bobId
                    + ", new state " + state);
            appComm.sendAuthMsg(authToBob);
            break;
        case AUTH_SENT:
            // intercept AuthBA (B -> A)
            if (!msg.getSrc().equals(bobId) || !msg.getDst().equals(anaId)) {
                sendFailMsg(msg.getSrc(),
                        "[AdvKeyEx: " + locId + "] Illegal peer in AUTH_SENT");
                return null;
            }

            try {
                // Derive session keys using adversary DH private key and Bob's public key
                genSessionKeys();
                // Attack successful: Bob believes peer is Ana,
                // but the established key is shared with the adversary
                success = true;
                state = AkeState.ESTABLISHED;
                Utils.trace("[AdvKeyEx: " + locId + "] Attack successful, state "
                        + state + ". Bob believes peer is " + anaId);
                // Abort session S1 explicitly using FAIL_B.
                sendFailMsgToAna("Session aborted");
                notifyTerminate();
            }
            catch (Exception e) {
                success = false;
                state = AkeState.FAILED;
                sendFailMsg(bobId,
                        "[AdvKeyEx: " + locId + "] Failed to derive forged session keys");
                e.printStackTrace();
                notifyTerminate();
            }
            break;
        case ESTABLISHED:
            break;
        case FAILED:
            break;
        default:
            sendFailMsg(msg.getSrc(),
                    "[AdvKeyEx: " + locId + "] Illegal state " + state);
        }
        return null;
    }

    /**
     * Not used in this protocol variant.
     */
    public byte[] recvInitAuthMsg(InitAuthMsg msg) throws Exception
    {
        sendFailMsg(msg.getSrc(),
                "[AdvKeyEx: " + locId + "] Illegal message");
        return null;
    }

    /**
     * Handles received FailMsg.
     *
     * If attack already succeeded, ignore late failure from Ana.
     * Otherwise terminate the adversary session.
     */
    public void recvFailMsg(FailMsg msg) throws Exception
    {
        Utils.trace("[AdvKeyEx: " + locId + "] recvFail, state " + state
                + ". From " + msg.getSrc() + ": " + msg.getReason());
        if (state != AkeState.ESTABLISHED) {
            state = AkeState.FAILED;
            success = false;
            notifyTerminate();
        }
    }

    /**
     * Sends FAIL_B directly to Ana without changing Adv's ESTABLISHED state.
     *
     * Adv plays Bob's role in session S1 with Ana, therefore the correct
     * message type is FAIL_B.
     */
    private void sendFailMsgToAna(String reason) throws Exception
    {
        Utils.trace("[AdvKeyEx: " + locId + "] sendFail to " + anaId + ": " + reason);
        FailMsg failMsg = new FailMsg(
                MsgType.FAIL_B,
                bobId,
                anaId,
                sidAtk,
                reason
        );
        appComm.sendFailMsg(failMsg);
    }

    /**
     * Generates session keys using DH shared secret between
     * adversary and B.
     *
     * The adversary obtains the same session key material as Bob.
     */
    protected void genSessionKeys() throws Exception
    {
        boolean isGCM = commonCrypto.getEncSecName().split("/")[1].equals("GCM");
        int secBytesLen = (isGCM ? 2 : 4) * commonCrypto.getSecKeyLen() / 8;
        // DH shared secret: (adv private, B public)
        byte[] secretBytesDH = KeyAgrDH.genDHSecret(
                commonCrypto.getDhName(),
                advDHKeyPair,
                bobDHPubBytes
        );
        // Na | Nb
        byte[] seed = Utils.concatenate(nonceA, nonceB);
        GenSessionKeyBytes genKeyBytes = new GenSessionKeyBytes(commonCrypto.getAutSecName());
        SecretKey kdk = genKeyBytes.extract(secretBytesDH, seed);
        byte[] randBytes = genKeyBytes.expand(kdk, seed, secBytesLen);
        setSessionKeys(randBytes);
        Utils.trace("[AdvKeyEx: " + locId + "] Generated session keys with Bob.");
    }
}

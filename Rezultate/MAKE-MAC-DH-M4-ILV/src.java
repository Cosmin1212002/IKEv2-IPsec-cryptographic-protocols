package secpro.psk;

import java.security.KeyPair;
import java.security.SecureRandom;

import javax.crypto.SecretKey;

import comm.AppComm;
import crypto.AutSec;
import crypto.GenSessionKeyBytes;
import crypto.KeyAgrDH;
import crypto.KeyManagerKS;
import misc.Utils;
import secpro.AkeState;
import secpro.CryptoConfig;
import secpro.OwnCrypto;
import secpro.SecProBase;
import secpro.SetupPSK;
import secpro.msg.AuthMsg;
import secpro.msg.InitAuthMsg;
import secpro.msg.InitMsg;
import secpro.msg.MsgType;

/**
 * MA-KE-MAC-IKE vulnerable variant with 4 messages.
 * Protocol with mutual authentication using MAC and PSK;
 * key exchange using ephemeral Diffie-Hellman.
 *
 * Vulnerable construction:
 * the MAC authenticator does not cover the full protocol transcript,
 * but only the peer identity, peer nonce and peer DH public key.
 *
 *
 */
public class MAkeMacIKEILV extends SecProBase
{
    // Diffie-Hellman
    private KeyPair locDHKeyPair;
    private byte[] remDHPubBytes;

    // AKE protocol
    private int nonceLen = 256;
    private byte[] locNonce;
    private byte[] remNonce;

    public MAkeMacIKEILV(AppComm appComm, String locId, byte[] sessionId,
            CryptoConfig commonCrypto, OwnCrypto ownCrypto) throws Exception
    {
        super(appComm, locId, sessionId, commonCrypto, ownCrypto);
    }

    /**
     * Initiator starts handshakes.
     */
    public void doKeyExch(String locId, String remId) throws Exception
    {
        if (state == AkeState.START) {
            this.remId = remId;
            initiator = true;
            generateNonceAndDHKeys();
            state = AkeState.INIT_SENT;
            appComm.sendInitMsg(buildInitMsg());
        }
    }

    /**
     * Builds InitMsg containing the sender's nonce and DH public key.
     * Variant with 4 messages: InitMsgA, InitMsgB, AuthMsgA, AuthMsgB.
     */
    protected InitMsg buildInitMsg() throws Exception
    {
        Utils.trace("[KeyEx: " + locId + "] build InitMsg to " + remId + ", new state " + state);
        // InitMsg contains local nonce and local ephemeral DH public key
        MsgType type = isInitiator() ? MsgType.INIT_A : MsgType.INIT_B;
        return new InitMsg(
                type,
                locId,
                remId,
                sessionId,
                locNonce,
                locDHKeyPair.getPublic().getEncoded(),
                null,
                null);
    }

    /**
     * Builds AuthMsg containing the sender's authenticator.
     * Variant with 4 messages: InitMsgA, InitMsgB, AuthMsgA, AuthMsgB.
     *
     * Vulnerable variant:
     * the authenticator (MAC) is sent directly, without authenticated
     * encryption and without additional data protection.
     */
    protected AuthMsg buildAuthMsg() throws Exception
    {
        Utils.trace("[KeyEx: " + locId + "] build AuthMsg to " + remId + ", new state " + state);
        byte[] mac = generateAuth();
        MsgType type = isInitiator() ? MsgType.AUTH_A : MsgType.AUTH_B;
        return new AuthMsg(type, locId, remId, sessionId, mac, null);
    }

    /**
     * Gets the PSK used for the main authenticator.
     *
     * The PSK is stored in the symmetric key store associated with the
     * local party, under alias remId + "_ake".
     */
    private SecretKey getAuthPsk() throws Exception
    {
        String ksFile = "keys/skeys/" + locId + ".pkcs12";
        KeyManagerKS ks = new KeyManagerKS(ksFile, SetupPSK.KS_PWD);
        ks.loadKeyStore();
        return ks.getSecretKey(remId + "_ake");
    }

    /**
     * Generates the local authenticator.
     *
     * Vulnerable construction:
     * the authenticator is a MAC with the PSK over:
     *   remId | remNonce | remDHPubKey
     *
     */
    protected byte[] generateAuth() throws Exception
    {
        AutSec authSec = new AutSec(commonCrypto.getAutSecName());
        authSec.setKey(getAuthPsk());
        byte[] data = Utils.concatenate(
                remId.getBytes(),
                remNonce,
                remDHPubBytes
        );
        return authSec.genMac(data);
    }

    /**
     * Verifies the received authenticator.
     *
     * Reconstructs the authenticated data:
     *   locId | locNonce | locDHPubKey
     * and verifies the MAC using the shared PSK.
     */
    protected boolean verifyAuth(byte[] auth) throws Exception
    {
        AutSec authSec = new AutSec(commonCrypto.getAutSecName());
        authSec.setKey(getAuthPsk());
        byte[] data = Utils.concatenate(
                locId.getBytes(),
                locNonce,
                locDHKeyPair.getPublic().getEncoded()
        );
        return authSec.verMac(data, auth);
    }

    /**
     * Processes received InitMsg.
     * Variant in 4 messages: InitMsgA, InitMsgB, AuthMsgA, AuthMsgB.
     */
    public byte[] recvInitMsg(InitMsg msg) throws Exception
    {
        Utils.trace("[KeyEx: " + locId + "] recv InitMsg in state " + state);

        switch (state) {
        case START:
            // Responder receives InitReqMsg
            // Store remote identity, nonce and DH public key
            remId = msg.getSrc();
            remNonce = msg.getNonce();
            remDHPubBytes = msg.getDHKey();
            generateNonceAndDHKeys();
            // Update state and send InitRspMsg
            state = AkeState.INIT_RCVD;
            appComm.sendInitMsg(buildInitMsg());
            // Generate session keys from DH shared secret
            genSessionKeys();
            break;
        case INIT_SENT:
            // Initiator receives InitRspMsg
            // Reject if response source does not match expected peer
            if (!msg.getSrc().equals(remId)) {
                sendFailMsg(msg.getSrc(), "[KeyEx: " + locId + "] Illegal peer");
                return null;
            }
            // Store remote nonce and DH public key
            remNonce = msg.getNonce();
            remDHPubBytes = msg.getDHKey();
            genSessionKeys();
            // Update state and send AuthReqMsg
            state = AkeState.AUTH_SENT;
            appComm.sendAuthMsg(buildAuthMsg());
            break;
        case ESTABLISHED:
            break;
        case FAILED:
            break;
        default:
            // abort: send FailMsg and terminate + fail
            sendFailMsg(remId, "[KeyEx: " + locId + "] Illegal state " + state);
        }
        return null;
    }

    /**
     * Processes received AuthMsg.
     * Variant in 4 messages: InitMsgA, InitMsgB, AuthMsgA, AuthMsgB.
     */
    public byte[] recvAuthMsg(AuthMsg msg) throws Exception
    {
        Utils.trace("[KeyEx: " + locId + "] recvAuth in state " + state);
        // Reject if message source does not match the expected peer
        if (!remId.equals(msg.getSrc())) {
            sendFailMsg(msg.getSrc(), "[KeyEx: " + locId + "] Illegal state");
            return null;
        }
        switch (state) {
        case INIT_RCVD:
            try {
                // Verify the received MAC authenticator
                success = verifyAuth(msg.getAuth());
                if (success) {
                    Utils.trace("[KeyEx: " + locId + "] Successful verification of " + remId
                            + "'s authenticator (MAC-PSK-DHE-VULN)\n  Successful authentication: remote user is " + remId);
                    // Send response AuthMsg
                    appComm.sendAuthMsg(buildAuthMsg());
                    state = AkeState.ESTABLISHED;
                    Utils.trace("[KeyEx: " + locId + "] Responder: Auth handshake done, state " + state + ". Success");
                    notifyTerminate();
                }
                else {
                    // Reject. Terminate.
                    Utils.trace("[KeyEx: " + locId + "] Failed authentication of " + remId);
                    sendFailMsg(remId, "Responder: Key exchange failed");
                }
            }
            catch (Exception e) {
                System.out.println("[KeyEx: " + locId + "]: Responder (recv AuthMsg). Key exchange failed (exception)");
                sendFailMsg(remId, "Responder: Key exchange failed");
                e.printStackTrace();
            }
            break;
        case AUTH_SENT:
            try {
                // Verify the received MAC authenticator
                success = verifyAuth(msg.getAuth());
                if (success) {
                    Utils.trace("[KeyEx: " + locId + "] Successful verification of " + remId
                            + "'s authenticator (MAC-PSK-DHE-VULN)\n  Successful authentication: remote user is " + remId);
                    state = AkeState.ESTABLISHED;
                    Utils.trace("[KeyEx: " + locId + "] Initiator: Auth handshake done, state " + state + ". Success");
                    notifyTerminate();
                }
                else {
                    // Reject. Terminate.
                    Utils.trace("[KeyEx: " + locId + "] Failed authentication of " + remId);
                    sendFailMsg(remId, "Initiator: Key exchange failed");
                }
            }
            catch (Exception e) {
                System.out.println("[KeyEx: " + locId + "]: Initiator (recv AuthMsg). Key exchange failed (exception)");
                sendFailMsg(remId, "Initiator: Key exchange failed");
                e.printStackTrace();
            }
            break;
        case ESTABLISHED:
            break;
        case FAILED:
            break;
        default:
            // abort: send FailMsg and terminate + fail
            sendFailMsg(remId, "[KeyEx: " + locId + "] Illegal state " + state);
        }
        return null;
    }

    /* Not used in 4-message variant */
    public byte[] recvInitAuthMsg(InitAuthMsg msg) throws Exception
    {
        sendFailMsg(remId, "[KeyEx: " + locId + "] Illegal message " + state);
        return null;
    }

    /**
     * Generates local protocol fresh values:
     * - random local nonce
     * - local ephemeral DH key pair
     */
    private void generateNonceAndDHKeys() throws Exception
    {
        SecureRandom rand = new SecureRandom();
        locNonce = new byte[nonceLen / 8];
        rand.nextBytes(locNonce);
        locDHKeyPair = KeyAgrDH.genDHKeyPair(commonCrypto.getDhName(), commonCrypto.getDhKeyLen());
        KeyAgrDH.printDHPublicKey("[KeyEx: " + locId + "] DH public key:\n", locDHKeyPair.getPublic());
    }

    /**
     * Generates session keys for authenticated-encryption (AE).
     *
     * Keys are derived from the DH shared secret using extract-and-expand.
     * Only data channel keys are generated (no additional authentication keys).
     */
    protected void genSessionKeys() throws Exception
    {
        boolean isGCM = commonCrypto.getEncSecName().split("/")[1].equals("GCM");
        int secBytesLen = (isGCM ? 2 : 4) * commonCrypto.getSecKeyLen() / 8;
        String dhName = commonCrypto.getDhName();
        byte[] secretBytesDH = KeyAgrDH.genDHSecret(dhName, locDHKeyPair, remDHPubBytes);
        byte[] seed = initiator
                ? Utils.concatenate(locNonce, remNonce)
                : Utils.concatenate(remNonce, locNonce);
        GenSessionKeyBytes genKeyBytes = new GenSessionKeyBytes(commonCrypto.getAutSecName());
        SecretKey kdk = genKeyBytes.extract(secretBytesDH, seed);
        byte[] randBytes = genKeyBytes.expand(kdk, seed, secBytesLen);
        setSessionKeys(randBytes);
    }
}

package secpro.pkc;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.PublicKey;

import javax.crypto.SecretKey;

import comm.AppComm;
import crypto.AutPub;
import crypto.GenSessionKeyBytes;
import crypto.KeyAgrDH;
import crypto.X509PKC;
import misc.Utils;
import secpro.AkeState;
import secpro.CryptoConfig;
import secpro.OwnCrypto;
import secpro.SecProBase;
import secpro.msg.AuthMsg;
import secpro.msg.InitAuthMsg;
import secpro.msg.InitMsg;
import secpro.msg.MsgType;

/**
 * MA-KE-SIG-PKC-DHE vulnerable variant with 4 messages.
 * Protocol with mutual authentication using digital signatures and
 * public-key certificates; key exchange using ephemeral Diffie-Hellman.
 *
 * Vulnerable construction:
 * the digital signature does not cover the full protocol transcript,
 * but only the peer identity, peer nonce and peer DH public key.
 *
 *
 */
public class MAkeSigIKEILV extends SecProBase
{
    // Diffie-Hellman
    private KeyPair locDHKeyPair;   // local DH key pair
    private byte[] remDHPubBytes;   // remote DH public key
    // Certificates
    private X509Certificate locCert;
    private X509Certificate remCert;
    // AKE protocol
    private int nonceLen = 256; // nonce bit-length
    private byte[] locNonce;
    private byte[] remNonce;

    public MAkeSigIKEILV(AppComm appComm, String locId, byte[] sessionId,
            CryptoConfig commonCrypto, OwnCrypto ownCrypto) throws Exception
    {
        super(appComm, locId, sessionId, commonCrypto, ownCrypto);
        locCert = X509PKC.getCert(ownCrypto.getCertFile());
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
     * Builds AuthMsg containing the sender's authenticator and certificate.
     * Variant with 4 messages: InitMsgA, InitMsgB, AuthMsgA, AuthMsgB.
     *
     * Vulnerable variant:
     * the authenticator is sent directly in AuthMsg, together with the
     * sender certificate, without authenticated encryption.
     */
    protected AuthMsg buildAuthMsg() throws Exception
    {
        Utils.trace("[KeyEx: " + locId + "] build AuthMsg to " + remId + ", new state " + state);
        // Compute own authenticator
        byte[] sig = generateAuth();
        MsgType type = isInitiator() ? MsgType.AUTH_A : MsgType.AUTH_B;
        return new AuthMsg(
                type,
                locId,
                remId,
                sessionId,
                sig,
                locCert.getEncoded(),
                null);
    }

    /**
     * Generates the local authenticator.
     *
     * Vulnerable construction:
     * the authenticator is a digital signature over:
     *   remId | remNonce | remDHPubKey
     *
     * The signed data does not include the complete transcript.
     */
    protected byte[] generateAuth() throws Exception
    {
        AutPub autPub = new AutPub(commonCrypto.getAutPubName());
        autPub.setPrivKey(
                ownCrypto.getKeyManager().getPrivateKey(
                        locId + commonCrypto.getSigPrivKeyAlias()
                )
        );
        byte[] data = Utils.concatenate(
                remId.getBytes(),
                remNonce,
                remDHPubBytes
        );
        return autPub.genSig(data);
    }

    /**
     * Verifies the received authenticator.
     *
     * Reconstructs the signed data:
     *   locId | locNonce | locDHPubKey
     * and verifies the remote digital signature using the public key
     * extracted from the received certificate.
     */
    protected boolean verifyAuth(byte[] auth) throws Exception
    {
        if (remCert == null) {
            return false;
        }
        verifyCert(remCert);
        byte[] data = Utils.concatenate(
                locId.getBytes(),
                locNonce,
                locDHKeyPair.getPublic().getEncoded()
        );
        AutPub autPub = new AutPub(commonCrypto.getAutPubName());
        autPub.setPubKey(remCert.getPublicKey());
        return autPub.verSig(data, auth);
    }

    /**
     * Processes received InitMsg.
     * Variant in 4 messages: InitMsgA, InitMsgB, AuthMsgA, AuthMsgB.
     * Different order of operations: optimistic/faster, pessimistic/slower.
     */
    public byte[] recvInitMsg(InitMsg msg) throws Exception
    {
        Utils.trace("[KeyEx: " + locId + "] recv InitMsg in state " + state);
        switch (state) {
        case START: // Responder receives InitReqMsg
            // Store remote identity, nonce and DH public key
            remId = msg.getSrc();
            remNonce = msg.getNonce();
            remDHPubBytes = msg.getDHKey();
            generateNonceAndDHKeys();
            // Update state and send InitRspMsg
            state = AkeState.INIT_RCVD; // InitMsg received and sent
            appComm.sendInitMsg(buildInitMsg());
            genSessionKeys(); // Variant: Before verifyAuth, faster
            break;
        case INIT_SENT: // Initiator receives InitRspMsg
            // Reject if response source does not match expected peer
            if (!msg.getSrc().equals(remId)) {
                sendFailMsg(msg.getSrc(), "[KeyEx: " + locId + "] Illegal peer");
                return null;
            }
            // Store remote nonce and DH public key
            remNonce = msg.getNonce();
            remDHPubBytes = msg.getDHKey();
            genSessionKeys(); // Variant: Before verifyAuth, faster
            // Update state and send AuthReqMsg
            state = AkeState.AUTH_SENT; // InitMsg sent and received, AuthMsg sent
            appComm.sendAuthMsg(buildAuthMsg());
            break;
        case ESTABLISHED: // terminated + success
            break; // ignore (abort?)
        case FAILED: // terminated + fail
            break; // ignore
        default: // abort: send FailMsg and terminate + fail
            sendFailMsg(remId, "[KeyEx: " + locId + "] Illegal state " + state); // -> state=FAILED
        }
        return null;
    }

    /**
     * Processes received AuthMsg.
     * Variant in 4 messages: InitMsgA, InitMsgB, AuthMsgA, AuthMsgB.
     * Different order of operations: optimistic/faster, pessimistic/slower.
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
        case INIT_RCVD: // responder
            try {
                // Verify the remote certificate from AuthMsg
                remCert = X509PKC.getCert(msg.getCert());

                // Verify the received digital signature
                success = verifyAuth(msg.getAuth());
                if (success) {
                    Utils.trace("[KeyEx: " + locId + "] Successful verification of " + remId
                            + "'s authenticator (SIG-PKC-DHE-ILV)\n"
                            + "  Successful authentication: remote user is " + remId);

                    // Variant: Send precomputed AuthRspMsg, faster
                    appComm.sendAuthMsg(buildAuthMsg());

                    state = AkeState.ESTABLISHED; // AuthMsg received and sent, success
                    Utils.trace("[KeyEx: " + locId + "] Responder: Auth handshake done, state "
                            + state + ". Success");
                    notifyTerminate();
                }
                else { // Reject. Terminate.
                    Utils.trace("[KeyEx: " + locId + "] Failed authentication of " + remId);
                    sendFailMsg(remId, "Responder: Key exchange failed"); // -> state=FAILED
                }
            }
            catch (Exception e) {
                System.out.println("[KeyEx: " + locId + "]: Responder (recv AuthMsg). Key exchange failed (exception)");
                sendFailMsg(remId, "Responder: Key exchange failed"); // -> state=FAILED
                e.printStackTrace();
            }
            break;

        case AUTH_SENT: // initiator
            try {
                // Verify the remote certificate from AuthMsg
                remCert = X509PKC.getCert(msg.getCert());
                // Verify the digital signature
                success = verifyAuth(msg.getAuth());
                if (success) {
                    Utils.trace("[KeyEx: " + locId + "] Successful verification of " + remId
                            + "'s authenticator (SIG-PKC-DHE-ILV)\n"
                            + "  Successful authentication: remote user is " + remId);
                    state = AkeState.ESTABLISHED; // AuthMsg received and sent, success
                    Utils.trace("[KeyEx: " + locId + "] Initiator: Auth handshake done, state "
                            + state + ". Success");
                    notifyTerminate();
                }
                else { // Reject. Terminate.
                    Utils.trace("[KeyEx: " + locId + "] Failed authentication of " + remId);
                    sendFailMsg(remId, "Initiator: Key exchange failed"); // -> state=FAILED
                }
            }
            catch (Exception e) {
                System.out.println("[KeyEx: " + locId + "]: Initiator (recv AuthMsg). Key exchange failed (exception)");
                sendFailMsg(remId, "Initiator: Key exchange failed"); // -> state=FAILED
                e.printStackTrace();
            }
            break;
        case ESTABLISHED: // terminated + success
            break; // ignore (abort?)
        case FAILED: // terminated + fail
            break; // ignore
        default: // abort: send FailMsg and terminate + fail
            sendFailMsg(remId, "[KeyEx: " + locId + "] Illegal state " + state); // -> state=FAILED
        }
        return null;
    }

    /* Not used in 4-message variant */
    public byte[] recvInitAuthMsg(InitAuthMsg msg) throws Exception
    {
        sendFailMsg(remId, "[KeyEx: " + locId + "] Illegal message " + state); // -> state=FAILED
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
     * Generates session keys for authenticated-encryption (AE) in
     * protocols that compute session keys using DH, nonces, and PRF.
     * These protocols use the extract and expand method: extract a
     * random secret from the DH secret and expand it when more random
     * bytes are necessary (longer keys, more keys).
     * The selected AE scheme determines the number of keys per data stream:
     * one key for dedicated AE scheme (GCM) or two keys for Encrypt-then-MAC
     * (EtM) generic construction with selected MAC and ENC-SEC schemes.
     *
     * Different keys for each direction.
     *
     * Vulnerable variant:
     * no additional keys are derived for MAC(locID) authenticators.
     */
    protected void genSessionKeys() throws Exception
    {
        // One key per direction if AE with selected dedicated scheme (GCM)
        // Two keys per direction if AE with EtM and selected ENC/MAC schemes
        boolean isGCM = commonCrypto.getEncSecName().split("/")[1].equals("GCM");
        int secBytesLen = (isGCM ? 2 : 4) * commonCrypto.getSecKeyLen() / 8;
        // Compute DH shared secret
        String dhName = commonCrypto.getDhName();
        byte[] secretBytesDH = KeyAgrDH.genDHSecret(dhName, locDHKeyPair, remDHPubBytes);
        byte[] seed = (initiator)
                ? Utils.concatenate(locNonce, remNonce)   // initiator
                : Utils.concatenate(remNonce, locNonce);  // responder
        // The PRF for key derivation is the selected MAC scheme
        GenSessionKeyBytes genKeyBytes = new GenSessionKeyBytes(commonCrypto.getAutSecName());
        SecretKey kdk = genKeyBytes.extract(secretBytesDH, seed);
        byte[] randBytes = genKeyBytes.expand(kdk, seed, secBytesLen);
        setSessionKeys(randBytes);
    }

    /**
     * Verifies a certificate: Gets from the key store the trusted
     * certificate of the issuer and verifies the CA signature of
     * the certificate. Verifies validity interval and subject name.
     * Throws an exception if the verification fails.
     */
    private void verifyCert(X509Certificate cert) throws Exception
    {
        X509Certificate issuerCert = ownCrypto.getKeyManager().getTrustedIssuerCert(cert);
        PublicKey issuerPubKey = issuerCert.getPublicKey();
        // Verify certificate signature with trusted issuer public key
        cert.verify(issuerPubKey);
        cert.checkValidity();
        String pkcSubName = cert.getSubjectX500Principal().getName();
        String pkcComName = pkcSubName.split(",")[0].split("=")[1];
        if (!remId.equals(pkcComName)) {
            throw new Exception("[KeyEx: " + locId + "] Invalid Certificate: Wrong Subject name");
        }
    }
}

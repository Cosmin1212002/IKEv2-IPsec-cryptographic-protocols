package secpro.psk;

import java.security.KeyPair;
import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import comm.AppComm;
import crypto.AutSec;
import crypto.GenSessionKeyBytes;
import crypto.KeyAgrDH;
import crypto.KeyManagerKS;
import crypto.ProtectedData;
import misc.Utils;
import secpro.AkeState;
import secpro.CryptoConfig;
import secpro.OwnCrypto;
import secpro.SecProBase;
import secpro.SetupPSK;
import secpro.msg.AuthData;
import secpro.msg.AuthMsg;
import secpro.msg.InitAuthMsg;
import secpro.msg.InitMsg;
import secpro.msg.MsgType;
import tests.TestConst;

/**
 * MA-KE-MAC-IKE: variant with 4 messages.
 * Protocol with mutual authentication using MAC and PSK;
 * key exchange using ephemeral Diffie-Hellman.
 *
 *
 *
 */
public class MAkeMacIKE extends SecProBase
{
    // Diffie-Hellman
    private KeyPair locDHKeyPair;
    private byte[] remDHPubBytes;
    // AKE protocol
    private int nonceLen = 256;
    private byte[] locNonce;
    private byte[] remNonce;
    // Session keys for MAC(locId) / MAC(remId)
    private SecretKey locKeyAuth;
    private SecretKey remKeyAuth;
    // Algorithm negotiation (simulated)
    private String locAlg;
    private String remAlg;
    //Data(msg)
    private byte[] locData;

    public MAkeMacIKE(AppComm appComm, String locId, byte[] sessionId,
            CryptoConfig commonCrypto, OwnCrypto ownCrypto) throws Exception
    {
        super(appComm, locId, sessionId, commonCrypto, ownCrypto);
        locAlg = commonCrypto.toString();
        remAlg = null;
        locData = null;
    }

    /**
     * Initiator starts handshakes.
     */
    public void doKeyExch(String locId, String remId) throws Exception
    {
        if (state == AkeState.START) {
            this.remId = remId;
            initiator = true;
            locData = TestConst.msg10.getBytes();
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
        // InitMsg contains alg, local nonce, local ephemeral DH public key,
        
        MsgType type = isInitiator() ? MsgType.INIT_A : MsgType.INIT_B;
        return new InitMsg(
                type,
                locId,
                remId,
                sessionId,
                locNonce,
                locDHKeyPair.getPublic().getEncoded(),
                null,
                locAlg.getBytes());
    }

    /**
     * Builds AuthMsg containing the sender's authenticator.
     * Variant with 4 messages: InitMsgA, InitMsgB, AuthMsgA, AuthMsgB.
     *
     * The authenticator and data are packed in AuthData and then
     * protected with authenticated encryption.
     */
    protected AuthMsg buildAuthMsg() throws Exception
    {
        Utils.trace("[KeyEx: " + locId + "] build AuthMsg to " + remId + ", new state " + state);
        // Compute own authenticator
        byte[] mac = generateAuth();
        // DataBA (responder)
        if (!isInitiator() && locData == null) {
            locData = TestConst.msg11.getBytes();
        }
        AuthData authData = new AuthData(null, mac, locData);
        ProtectedData encAuthData = autEncSend.encrypt(authData.encode());
        MsgType type = isInitiator() ? MsgType.AUTH_A : MsgType.AUTH_B;
        return new AuthMsg(type, locId, remId, sessionId, null, null, encAuthData);
    }

    /**
     * Gets the PSK used for the main authenticator.
     *
     * The PSK is stored in the symmetric key store associated with the
     * local party, under alias remId + "_ake".
     */
    private SecretKey getAuthPsk() throws Exception
    {
        //String ksFile = "keys/skeys/" + locId + ".pkcs12";
        //KeyManagerKS ks = new KeyManagerKS(ksFile, SetupPSK.KS_PWD);
        //ks.loadKeyStore();
        //return ks.getSecretKey(remId + "_ake");
       SecretKey kauKey = ownCrypto.getKeyManager().getSecretKey(remId + "_ake");
       return kauKey;
    }

    /**
     * Generates the local authenticator.
     *
     * The authenticator is a MAC with the pre-shared key over:
     *   alg | locNonce | locDHPubKey | remNonce | MAC(locId)
     *
     * The internal MAC(locId) is computed with a session key derived from
     * the DH shared secret and provides additional key confirmation.
     */
    protected byte[] generateAuth() throws Exception
    {
        // Compute MAC(locId) with the local authentication session key
        AutSec authSecId = new AutSec(commonCrypto.getAutSecName());
        authSecId.setKey(locKeyAuth);
        byte[] macId = authSecId.genMac(locId.getBytes());
        // Main MAC authenticator with PSK
        AutSec authSec = new AutSec(commonCrypto.getAutSecName());
        SecretKey kauKey = getAuthPsk();
        authSec.setKey(kauKey);
        // Build the authenticated transcript:
        // alg | nonce | DH | nonce | MAC
        byte[] data = Utils.concatenate(locAlg.getBytes(), locNonce);
        data = Utils.concatenate(data, locDHKeyPair.getPublic().getEncoded());
        data = Utils.concatenate(data, remNonce, macId);
        return authSec.genMac(data);
    }

    /**
     * Verifies the received authenticator.
     *
     * Reconstructs the authenticated transcript:
     *   remAlg | remNonce | remDHPubKey | locNonce | MAC(remId)
     * and verifies the received MAC using the shared PSK.
     */
    protected boolean verifyAuth(byte[] auth) throws Exception
    {
        // Recompute MAC(remId) with the remote authentication session key
        AutSec authSecId = new AutSec(commonCrypto.getAutSecName());
        authSecId.setKey(remKeyAuth);
        byte[] remIdMac = authSecId.genMac(remId.getBytes());
        // Main MAC authenticator with PSK
        AutSec authSec = new AutSec(commonCrypto.getAutSecName());
        SecretKey kauKey = getAuthPsk();
        authSec.setKey(kauKey);
        byte[] data = Utils.concatenate(remAlg.getBytes(), remNonce);
        data = Utils.concatenate(data, remDHPubBytes);
        data = Utils.concatenate(data, locNonce, remIdMac);

        return authSec.verMac(data, auth);
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
        case START:
            // Responder receives InitReqMsg
            // Store remote identity, nonce, DH public key and algorithm
            remId = msg.getSrc();
            remNonce = msg.getNonce();
            remDHPubBytes = msg.getDHKey();
            remAlg = (msg.getAlg() == null)
                    ? null
                    : new String(msg.getAlg());

            if (remAlg == null || !remAlg.equals(locAlg)) {
                sendFailMsg(remId, "Algorithm mismatch");
                return null;
            }
            // DataBA
            locData = TestConst.msg11.getBytes();
            generateNonceAndDHKeys();
            // Update state and send InitRspMsg
            state = AkeState.INIT_RCVD;
            appComm.sendInitMsg(buildInitMsg());
            // Variant: Before verifyAuth, faster
            genSessionKeys();
            break;
        case INIT_SENT:
            // Initiator receives InitRspMsg
            // Reject if response source does not match expected peer
            if (!msg.getSrc().equals(remId)) {
                sendFailMsg(msg.getSrc(), "[KeyEx: " + locId + "] Illegal peer");
                return null;
            }
            // Store remote nonce, DH public key and algorithm
            remNonce = msg.getNonce();
            remDHPubBytes = msg.getDHKey();
            remAlg = (msg.getAlg() == null)
                    ? null
                    : new String(msg.getAlg());

            if (remAlg == null || !remAlg.equals(locAlg)) {
                sendFailMsg(remId, "Algorithm mismatch");
                return null;
            }
            // Variant: Before verifyAuth, faster
            genSessionKeys();
            // Update state and send AuthReqMsg
            state = AkeState.AUTH_SENT;// InitMsg sent and received, AuthMsg sent
            appComm.sendAuthMsg(buildAuthMsg());
            break;
        case ESTABLISHED: // terminated + success
            break; //ignore (abort?)
        case FAILED: // terminated + fail
            break;// ignore
        default:
            // abort: send FailMsg and terminate + fail
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
        byte[] ptxt = null; // AuthMsg with early data
        // sw.start();
        switch (state) {
        case INIT_RCVD: // responder
            try {
            	// sw.printDeltaTime("Responder recvAuthMsg");
                AuthData authData = new AuthData(autEncRecv.decrypt(msg.getEData()));
                // Verify the received MAC authenticator
                success = verifyAuth(authData.getAuth());
                if (success) {
                    Utils.trace("[KeyEx: " + locId + "] Successful verification of " + remId
                            + "'s authenticator (MAC)\n  Successful authentication: remote user is " + remId);
                    // AuthMsg with early data
					ptxt =  authData.getData();
					Utils.trace("[KeyEx: "+locId+"] Received early data: " + new String(ptxt));
                    // Variant: Send precomputed AuthRspMsg, faster
                    appComm.sendAuthMsg(buildAuthMsg());
                    state = AkeState.ESTABLISHED;
                    // sw.printElapsedTime("Responder duration");
                    Utils.trace("[KeyEx: " + locId + "] Responder: Auth handshake done, state " + state + ". Success");
                    notifyTerminate();
                }
                else {
                    // Reject. Terminate.
                    Utils.trace("[KeyEx: " + locId + "] Failed authentication of " + remId);
                    sendFailMsg(remId, "Responder: Key exchange failed");// -> state=FAILED
                }
            }
            catch (Exception e) {
                System.out.println("[KeyEx: " + locId + "]: Responder (recv AuthMsg). Key exchange failed (exception)");
                sendFailMsg(remId, "Responder: Key exchange failed");// -> state=FAILED
                e.printStackTrace();
            }
            break;

        case AUTH_SENT: // initiator
            try {
            	// sw.printDeltaTime("Initiator recvAuthMsg");
                AuthData authData = new AuthData(autEncRecv.decrypt(msg.getEData()));
                // Verify the received MAC authenticator
                success = verifyAuth(authData.getAuth());
                if (success) {
                    Utils.trace("[KeyEx: " + locId + "] Successful verification of " + remId
                            + "'s authenticator (MAC)\n  Successful authentication: remote user is " + remId);
                    state = AkeState.ESTABLISHED;// AuthMsg received and sent, success
                    // sw.printElapsedTime("Initiator total duration");
                    Utils.trace("[KeyEx: " + locId + "] Initiator: Auth handshake done, state " + state + ". Success");
                    // AuthMsg with early data
					ptxt =  authData.getData();
					Utils.trace("[KeyEx: "+locId+"] Received early data: " + new String(ptxt));
                    notifyTerminate();
                }
                else {
                    // Reject. Terminate.
                    Utils.trace("[KeyEx: " + locId + "] Failed authentication of " + remId);
                    sendFailMsg(remId, "Initiator: Key exchange failed");// -> state=FAILED
                }
            }
            catch (Exception e) {
                System.out.println("[KeyEx: " + locId + "]: Initiator (recv AuthMsg). Key exchange failed (exception)");
                sendFailMsg(remId, "Initiator: Key exchange failed");// -> state=FAILED
                e.printStackTrace();
            }
            break;
        case ESTABLISHED:// terminated + success
            break;// ignore (abort?)
        case FAILED:// terminated + fail
            break;// ignore
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
     * Additional keys for MAC(locID) authenticator.
     */
    protected void genSessionKeys() throws Exception
    {
        // One key per direction if AE with selected dedicated scheme (GCM)
        // Two keys per direction if AE with EtM and selected ENC/MAC schemes
        // Two additional keys for local/remote authenticator (MAC(id))
        int keyLen = commonCrypto.getSecKeyLen() / 8;
        boolean isGCM = commonCrypto.getEncSecName().split("/")[1].equals("GCM");
        int randBytesLen = (isGCM ? 4 : 6) * keyLen;
        String macName = commonCrypto.getAutSecName();
        // Compute DH shared secret
        String dhName = commonCrypto.getDhName();
        byte[] secretBytesDH = KeyAgrDH.genDHSecret(dhName, locDHKeyPair, remDHPubBytes);

        byte[] seed = initiator
                ? Utils.concatenate(locNonce, remNonce)
                : Utils.concatenate(remNonce, locNonce);
        // The PRF for key derivation is the selected MAC scheme
        GenSessionKeyBytes genKeyBytes = new GenSessionKeyBytes(macName);

        SecretKey kdk = genKeyBytes.extract(secretBytesDH, seed);
        byte[] randBytes = genKeyBytes.expand(kdk, seed, randBytesLen);
        // Keys for local/remote authenticator and for data send/receive
        byte[] authRandBytes = new byte[2 * keyLen];
        byte[] dataRandBytes = new byte[randBytesLen - 2 * keyLen];
        Utils.split(randBytes, authRandBytes, dataRandBytes);
        byte[][] authKeyBytes = new byte[2][keyLen];
        Utils.split(authRandBytes, authKeyBytes);

        locKeyAuth = new SecretKeySpec(authKeyBytes[initiator ? 0 : 1], macName);
        remKeyAuth = new SecretKeySpec(authKeyBytes[initiator ? 1 : 0], macName);
        setSessionKeys(dataRandBytes);
    } 
    
}

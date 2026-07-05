package secpro.psk;

import java.security.KeyPair;
import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import comm.AppComm;
import crypto.AutEnc;
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
import secpro.msg.AuthMsg;
import secpro.msg.InitAuthMsg;
import secpro.msg.InitMsg;
import secpro.msg.MsgType;

/**
 * MAKE-ESP-MAC-PSK-DHE: 2-message protocol.
 *
 * Protocol used after an IKE SA was already established.
 * Peers are already authenticated and use an existing PSK only to
 * protect the new keying material with authenticated encryption.
 *
 * The AE-protected payload is carried in InitMsg.eData.
 *
 */
public class MAkeMacESP extends SecProBase
{
    // Diffie-Hellman
    private KeyPair locDHKeyPair;
    private byte[] remDHPubBytes;
    // AKE protocol
    private final int nonceLen = 256;
    private byte[] locNonce;
    private byte[] remNonce;
    // Algorithm negotiation (simulated)
    private String locAlg;
    private String remAlg;
    // AE protected with a key derived from the PSK
    private AutEnc aeWithPsk;

    public MAkeMacESP(AppComm appComm, String locId, byte[] sessionId,
            CryptoConfig commonCrypto, OwnCrypto ownCrypto) throws Exception
    {
        super(appComm, locId, sessionId, commonCrypto, ownCrypto);
        locAlg = commonCrypto.toString();
        remAlg = null;
    }

    /**
     * Initiator starts the 2-message exchange.
     */
    public void doKeyExch(String locId, String remId) throws Exception
    {
        if (state == AkeState.START) {
            this.remId = remId;
            initiator = true;
            initAeWithPsk();
            generateNonceAndDHKeys();
            state = AkeState.INIT_SENT;
            appComm.sendInitMsg(buildInitMsg());
        }
    }

    /**
     * Initializes AE with key material derived from the PSK.
     * a single PSK-derived AE key set is used in both directions.
     */
    private void initAeWithPsk() throws Exception
    {
        SecretKey psk = getEspPsk();
        String macName = commonCrypto.getAutSecName();
        String encName = commonCrypto.getEncSecName();
        int keyLen = commonCrypto.getSecKeyLen() / 8;
        boolean isGCM = encName.split("/")[1].equals("GCM");
        // Symmetric seed so both peers derive the same AE key set
        String id1 = (locId.compareTo(remId) <= 0) ? locId : remId;
        String id2 = (locId.compareTo(remId) <= 0) ? remId : locId;
        byte[] seed = Utils.concatenate(
                id1.getBytes(),
                id2.getBytes());
        GenSessionKeyBytes genKeyBytes = new GenSessionKeyBytes(macName);
        SecretKey kdk = genKeyBytes.extract(psk.getEncoded(), seed);
        int numKeyBytes = isGCM ? keyLen : 2 * keyLen;
        byte[] derivedBytes = genKeyBytes.expand(kdk, seed, numKeyBytes);
        String encAlgName = encName.split("/")[0];
        aeWithPsk = new AutEnc(encName, macName);
        aeWithPsk.setKeyEnc(new SecretKeySpec(derivedBytes, 0, keyLen, encAlgName));
        if (!isGCM) {
            aeWithPsk.setKeyMac(new SecretKeySpec(derivedBytes, keyLen, keyLen, macName));
        }
    }

    /**
     * Gets the PSK used for AE protection of INIT messages.
     * Stored under alias remId + "_ake" in the local key store.
     */
    private SecretKey getEspPsk() throws Exception
    {
        String ksFile = "keys/skeys/" + locId + ".pkcs12";
        KeyManagerKS ks = new KeyManagerKS(ksFile, SetupPSK.KS_PWD);
        ks.loadKeyStore();
        return ks.getSecretKey(remId + "_ake");
    }

    /**
     * Builds INIT_A / INIT_B carrying:
     *   eData = AE(alg | nonce | dhKey)
     */
    protected InitMsg buildInitMsg() throws Exception
    {
        Utils.trace("[KeyEx: " + locId + "] build InitMsg to " + remId + ", new state " + state);
        byte[] dhPubBytes = locDHKeyPair.getPublic().getEncoded();
        byte[] payload = encodeInitData(locAlg, locNonce, dhPubBytes);
        ProtectedData encData = aeWithPsk.encrypt(payload);
        MsgType type = isInitiator() ? MsgType.INIT_A : MsgType.INIT_B;
        return new InitMsg(
                type,
                locId,
                remId,
                sessionId,
                null,
                null,
                null,
                null,
                encData
        );
    }

    /**
     * Processes received InitMsg.
     */
    public byte[] recvInitMsg(InitMsg msg) throws Exception
    {
        Utils.trace("[KeyEx: " + locId + "] recv InitMsg in state " + state);
        switch (state) {
        case START:
            // Responder receives INIT_A
            remId = msg.getSrc();
            initiator = false;
            initAeWithPsk();
            if (!verifyAndExtract(msg)) {
                sendFailMsg(remId, "[KeyEx: " + locId + "] AE verification failed on InitMsg");
                return null;
            }
            generateNonceAndDHKeys();
            genSessionKeys();
            // Reuse generic INIT_SENT state before sending INIT_B
            state = AkeState.INIT_SENT;
            appComm.sendInitMsg(buildInitMsg());
            state = AkeState.ESTABLISHED;
            success = true;
            Utils.trace("[KeyEx: " + locId + "] Responder: handshake done, state "
                    + state + ". Success");
            notifyTerminate();
            break;
        case INIT_SENT:
            // Initiator receives INIT_B
            if (!msg.getSrc().equals(remId)) {
                sendFailMsg(msg.getSrc(), "[KeyEx: " + locId + "] Illegal peer in state INIT_SENT");
                return null;
            }
            if (!verifyAndExtract(msg)) {
                sendFailMsg(remId, "[KeyEx: " + locId + "] AE verification failed on InitMsg");
                return null;
            }
            genSessionKeys();
            state = AkeState.ESTABLISHED;
            success = true;
            Utils.trace("[KeyEx: " + locId + "] Initiator: handshake done, state "
                    + state + ". Success");
            notifyTerminate();
            break;
        case ESTABLISHED: // terminated + success
            break;//ignore (abort?)
        case FAILED: // terminated + fail
            break; // ignore
        default:
        	// abort: send FailMsg and terminate + fail
            sendFailMsg(remId, "[KeyEx: " + locId + "] Illegal state " + state); // -> state=FAILED
        }
        return null;
    }

    /**
     * Decrypts and verifies the AE-protected init payload and extracts:
     *   remAlg, remNonce, remDHPubBytes
     * Checks remAlg == locAlg.
     */
    private boolean verifyAndExtract(InitMsg msg)
    {
        ProtectedData eData = msg.getEData();
        if (eData == null) {
            return false;
        }
        try {
            byte[] plaintext = aeWithPsk.decrypt(eData);
            if (plaintext == null || plaintext.length < 6) {
                return false;
            }
            decodeInitData(plaintext);

            if (remAlg == null || !remAlg.equals(locAlg)) {
                Utils.trace("[KeyEx: " + locId + "] Algorithm mismatch: local=" + locAlg
                        + ", remote=" + remAlg);
                return false;
            }
            if (remNonce == null || remNonce.length != nonceLen / 8) {
                return false;
            }
            if (remDHPubBytes == null || remDHPubBytes.length == 0) {
                return false;
            }
            return true;
        }
        catch (Exception e) {
            Utils.trace("[KeyEx: " + locId + "] AE verification failed: " + e.getMessage());
            return false;
        }
    }

    public byte[] recvInitAuthMsg(InitAuthMsg msg) throws Exception
    {
        sendFailMsg(remId, "[KeyEx: " + locId + "] Unexpected InitAuthMsg in state " + state);
        return null;
    }

    public byte[] recvAuthMsg(AuthMsg msg) throws Exception
    {
        sendFailMsg(remId, "[KeyEx: " + locId + "] Unexpected AuthMsg in state " + state);
        return null;
    }

    /**
     * Generates local nonce and ephemeral DH key pair.
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
     * Generates session keys for the new ESP SA using DH and nonces.
     *
     * K_S = PRF_N(g^xy), where N = N_A | N_B
     * two keys per direction for EtM.
     */
    protected void genSessionKeys() throws Exception
    {
        int keyLen = commonCrypto.getSecKeyLen() / 8;
        boolean isGCM = commonCrypto.getEncSecName().split("/")[1].equals("GCM");
        int randBytesLen = (isGCM ? 2 : 4) * keyLen;
        String macName = commonCrypto.getAutSecName();
        // Compute DH shared secret
        String dhName = commonCrypto.getDhName();
        byte[] secretBytesDH = KeyAgrDH.genDHSecret(dhName, locDHKeyPair, remDHPubBytes);
        byte[] seed = initiator
                ? Utils.concatenate(locNonce, remNonce)
                : Utils.concatenate(remNonce, locNonce);
        // The PRF for key derivation
        GenSessionKeyBytes genKeyBytes = new GenSessionKeyBytes(macName);
        SecretKey kdk = genKeyBytes.extract(secretBytesDH, seed);
        byte[] randBytes = genKeyBytes.expand(kdk, seed, randBytesLen);
        setSessionKeys(randBytes);
    }

    /**
     * Encodes: alg | nonce | dhKey
     * as: [2B algLen][alg][2B nonceLen][nonce][2B dhLen][dhKey]
     */
    private byte[] encodeInitData(String alg, byte[] nonce, byte[] dhKey)
    {
        byte[] algBytes = (alg == null) ? null : alg.getBytes();

        int algLen = (algBytes == null) ? 0 : algBytes.length;
        int nonceLen = (nonce == null) ? 0 : nonce.length;
        int dhLen = (dhKey == null) ? 0 : dhKey.length;
        int encodedLen = 6 + algLen + nonceLen + dhLen;
        byte[] encodedBytes = new byte[encodedLen];
        int pos = 0;
        System.arraycopy(Utils.int16ToBytes(algLen), 0, encodedBytes, pos, 2);
        pos += 2;
        if (algBytes != null) {
            System.arraycopy(algBytes, 0, encodedBytes, pos, algLen);
            pos += algLen;
        }
        System.arraycopy(Utils.int16ToBytes(nonceLen), 0, encodedBytes, pos, 2);
        pos += 2;
        if (nonce != null) {
            System.arraycopy(nonce, 0, encodedBytes, pos, nonceLen);
            pos += nonceLen;
        }
        System.arraycopy(Utils.int16ToBytes(dhLen), 0, encodedBytes, pos, 2);
        pos += 2;
        if (dhKey != null) {
            System.arraycopy(dhKey, 0, encodedBytes, pos, dhLen);
        }
        return encodedBytes;
    }

    /**
     * Decodes: [2B algLen][alg][2B nonceLen][nonce][2B dhLen][dhKey]
     * and stores the received values in: remAlg, remNonce, remDHPubBytes
     */
    private void decodeInitData(byte[] encodedBytes) throws Exception
    {
        int pos = 0;
        if (encodedBytes == null || encodedBytes.length < 6) {
            throw new IllegalArgumentException("Invalid init data");
        }
        int len = Utils.bytesToInt16(new byte[] { encodedBytes[pos], encodedBytes[pos + 1] });
        pos += 2;
        if (len <= 0 || pos + len > encodedBytes.length) {
            throw new IllegalArgumentException("Invalid alg length");
        }
        byte[] algBytes = new byte[len];
        System.arraycopy(encodedBytes, pos, algBytes, 0, len);
        remAlg = new String(algBytes);
        pos += len;
        len = Utils.bytesToInt16(new byte[] { encodedBytes[pos], encodedBytes[pos + 1] });
        pos += 2;
        if (len <= 0 || pos + len > encodedBytes.length) {
            throw new IllegalArgumentException("Invalid nonce length");
        }
        remNonce = new byte[len];
        System.arraycopy(encodedBytes, pos, remNonce, 0, len);
        pos += len;
        len = Utils.bytesToInt16(new byte[] { encodedBytes[pos], encodedBytes[pos + 1] });
        pos += 2;
        if (len <= 0 || pos + len > encodedBytes.length) {
            throw new IllegalArgumentException("Invalid DH key length");
        }
        remDHPubBytes = new byte[len];
        System.arraycopy(encodedBytes, pos, remDHPubBytes, 0, len);
        pos += len;
        if (pos != encodedBytes.length) {
            throw new IllegalArgumentException("Trailing bytes in init data");
        }
    }
}

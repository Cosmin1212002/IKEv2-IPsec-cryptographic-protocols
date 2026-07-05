package secpro.pkc;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.PublicKey;
import crypto.AutPub;

import comm.AppComm;
import crypto.AutSec;
import crypto.GenSessionKeyBytes;
import crypto.KeyAgrDH;
import crypto.ProtectedData;
import crypto.X509PKC;
import misc.Utils;
import secpro.AkeState;
import secpro.CryptoConfig;
import secpro.OwnCrypto;
import secpro.SecProBase;
import secpro.msg.AuthData;
import secpro.msg.AuthMsg;
import secpro.msg.InitAuthMsg;
import secpro.msg.InitMsg;
import secpro.msg.MsgType;
import tests.TestConst;

/**
 * MA-KE-SIG-PKC-DHE: variant with 4 messages.
 * Protocol with mutual authentication using digital signatures and
 * public-key certificates; key exchange using ephemeral Diffie-Hellman. 
 * 
 *
 */

public class MAkeSigIKE extends SecProBase
{
	// Diffie-Hellman
    private KeyPair locDHKeyPair;  // local DH key pair
    private byte[] remDHPubBytes; // remote DH public key
    // Certificates
    private X509Certificate locCert;
    private X509Certificate remCert;
    // AKE protocol
    private int nonceLen = 256; // nonce bit-length
    private byte[] locNonce;
    private byte[] remNonce;
    // Session key for MAC(locId)
    private SecretKey locKeyAuth;   // MAC key for own authenticator
    private SecretKey remKeyAuth;  // MAC key for remote authenticator
    // Algorithm negotiation 
    private String locAlg;
    private String remAlg;
    //Data(msg)
    private byte[] locData;


    public MAkeSigIKE(AppComm appComm, String locId, byte[] sessionId,
            CryptoConfig commonCrypto, OwnCrypto ownCrypto) throws Exception
    {
        super(appComm, locId, sessionId, commonCrypto, ownCrypto);
        locCert = X509PKC.getCert(ownCrypto.getCertFile());
        locAlg = commonCrypto.toString();
        remAlg = null;
        locData = null;
    }
	
	/**
	 * Initiator starts handshakes. 
	 */
    public void doKeyExch(String locId, String remId) throws Exception
	{
		// sw.start(); // start stopwatch for initiator
		// InitMsg handshake
    	if (state == AkeState.START) {
            this.remId = remId;
            initiator = true;
            locData = TestConst.msg10.getBytes(); 
			//generare nonce si DH
			generateNonceAndDHKeys();
			state = AkeState.INIT_SENT;  
			appComm.sendInitMsg(buildInitMsg()); 
		}
	}


	/**
	 * Builds InitMsg containing the sender's alg, nonce and DH public key.  
	 * Variant with 4 messages: InitMsgA, InitMsgB, AuthMsgA, AuthMsgB. 
	 */
    protected InitMsg buildInitMsg() throws Exception
	{ 
    	 Utils.trace("[KeyEx: "+locId+"] build InitMsg to " + remId + ", new state " + state);
		// InitMsg contains local alg, local nonce and local ephemeral DH public key
		MsgType type = isInitiator()? MsgType.INIT_A : MsgType.INIT_B;
		return new InitMsg(type, locId, remId, sessionId,
                locNonce,
                locDHKeyPair.getPublic().getEncoded(),
                null,
                locAlg.getBytes());  
	}

	/**
	 * Builds AuthMsg containing the sender's authenticator and certificate. 
	 * Variant with 4 messages: InitMsgA, InitMsgB, AuthMsgA, AuthMsgB. 
	 */
    protected AuthMsg buildAuthMsg() throws Exception
	{
    	Utils.trace("[KeyEx: "+locId+"] build AuthMsg to " + remId + ", new state " + state);
		// Compute own authenticator
		byte[] sig = generateAuth(); 
		// DataBA (responder)
        if (!isInitiator() && locData == null) {
            locData = TestConst.msg11.getBytes();
        }

        AuthData authData = new AuthData(
                locCert.getEncoded(),
                sig,
                locData
        );
        // AE encryption
        ProtectedData encAuthData = autEncSend.encrypt(authData.encode());
        MsgType type = isInitiator() ? MsgType.AUTH_A : MsgType.AUTH_B;
        return new AuthMsg(type, locId, remId, sessionId,
                null, null, encAuthData); 
	}
	
    /**
	 * Generates the local authenticator.
	 * 
	 * The authenticator is a digital signature over:
	 *  locAlg | locNonce | locDHPubKey | remNonce | MAC(locId)
	 * 
	 * The internal MAC(locId) is computed with a session key derived from
	 * the DH shared secret and provides key confirmation.
	 */
    protected byte[] generateAuth() throws Exception
	{
    	// Compute MAC(locId) with the local authentication session key
    	AutSec authSec = new AutSec(commonCrypto.getAutSecName());
        authSec.setKey(locKeyAuth);
        byte[] mac = authSec.genMac(locId.getBytes());

    		// SIG authenticator
        AutPub autPub = new AutPub(commonCrypto.getAutPubName());
        autPub.setPrivKey(
                ownCrypto.getKeyManager().getPrivateKey(
                        locId + commonCrypto.getSigPrivKeyAlias()
                )
    		);
    		// Build the signed transcript:
        	// alg | nonce | DH | nonce | MAC
        byte[] data = Utils.concatenate(locAlg.getBytes(), locNonce);
        data = Utils.concatenate(data, locDHKeyPair.getPublic().getEncoded());
        data = Utils.concatenate(data, remNonce, mac);

        return autPub.genSig(data);
	}
	
    /**
	 * Verifies the received authenticator.
	 * 
	 * Reconstructs the signed transcript:
	 * remAlg | remNonce | remDHPubKey | locNonce | MAC(remId)
	 * and verifies the remote digital signature using the public key
	 * extracted from the received certificate.
	 */
    protected boolean verifyAuth(byte[] auth) throws Exception
    {
    	if (remCert == null) {
    		return false;
    	}

    	verifyCert(remCert);
    	// Recompute MAC(remId) with the remote authentication session key
    	byte[] remIdMac = verifyIdMac();
    	byte[] data = Utils.concatenate(remAlg.getBytes(), remNonce);
        data = Utils.concatenate(data, remDHPubBytes);
        data = Utils.concatenate(data, locNonce, remIdMac);
    	// Verify the signature using the public key from the remote certificate
    	AutPub authPub = new AutPub(commonCrypto.getAutPubName());
    	authPub.setPubKey(remCert.getPublicKey());
    	return authPub.verSig(data, auth);
    }
	
	/**
	 * Processes received InitMsg. 
	 * Variant in 4 messages: InitMsgA, InitMsgB, AuthMsgA, AuthMsgB. 
	 * Different order of operations: optimistic/faster, pessimistic/slower. 
	 */
    public byte[] recvInitMsg(InitMsg msg) throws Exception
	{
		Utils.trace("[KeyEx: "+locId+"] recv InitMsg in state " + state); 
		switch (state) {
		case START: // Responder receives InitReqMsg
			// Store remote alg, identity, nonce and DH public key
			remId = msg.getSrc(); 
			remNonce = msg.getNonce(); 
			remDHPubBytes = msg.getDHKey();
			remAlg = (msg.getAlg() == null) ?
                    null :
                    new String(msg.getAlg());
            if (remAlg == null || !remAlg.equals(locAlg)) {
                sendFailMsg(remId, "Algorithm mismatch");
                return null;
            }
            // DataBA
            locData = TestConst.msg11.getBytes();
			generateNonceAndDHKeys();
			// Update state and send InitRspMsg 
			state = AkeState.INIT_RCVD; // InitMsg received and sent
			appComm.sendInitMsg(buildInitMsg()); 
			genSessionKeys(); // Variant: Before verifyAuth, faster
			break;
		case INIT_SENT: // Initiator receives InitRspMsg
			// Store remote alg, nonce and DH public key
			remNonce = msg.getNonce(); 
			remDHPubBytes = msg.getDHKey();
			remAlg = (msg.getAlg() == null) ?
                    null :
                    new String(msg.getAlg());

            if (remAlg == null || !remAlg.equals(locAlg)) {
                sendFailMsg(remId, "Algorithm mismatch");
                return null;
            }
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
			sendFailMsg(remId, "[KeyEx: "+locId+"] Illegal state " + state); // -> state=FAILED
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
		Utils.trace("[KeyEx: "+locId+"] recvAuth in state " + state);
		// Reject if message source does not match the expected peer
		if (!remId.equals(msg.getSrc())) {
			sendFailMsg(msg.getSrc(), "[KeyEx: "+locId+"] Illegal state"); 
			return null;
		}
		byte[] ptxt = null; //AuthMsg with early data
		switch(state) { 
		case INIT_RCVD: // responder
			try {
				// sw.printDeltaTime("Responder recvAuthMsg");
				AuthData authData = new AuthData(autEncRecv.decrypt(msg.getEData()));
                remCert = X509PKC.getCert(authData.getCert());
				// Verify the received digital signature
                success = verifyAuth(authData.getAuth()); 
				if (success) { 
					Utils.trace("[KeyEx: "+locId+"] Successful verification of " + remId + "'s authenticator (SIG)\n"
                            + "  Successful authentication: remote user is " + remId);
					//AuthMsg with early data
					ptxt =  authData.getData();
					Utils.trace("[KeyEx: "+locId+"] Received early data: " + new String(ptxt)); 
					// Variant: Send precomputed AuthRspMsg, faster
					appComm.sendAuthMsg(buildAuthMsg()); 
					state = AkeState.ESTABLISHED; // AuthMsg received and sent, success
					// sw.printElapsedTime("Responder duration");
					Utils.trace("[KeyEx: "+locId+"] Responder: Auth handshake done, state " 
							+ state + ". Success");
					notifyTerminate(); 
				}
				else { // Reject. Terminate. 
					Utils.trace("[KeyEx: "+locId+"] Failed authentication of " + remId); 
					sendFailMsg(remId, "Responder: Key exchange failed"); // -> state=FAILED
				}
			}
			catch (Exception e) { 
				System.out.println("[KeyEx: "+locId + "]: Responder (recv AuthMsg). Key exchange failed (exception)"); 
				sendFailMsg(remId, "Responder: Key exchange failed"); // -> state=FAILED
				e.printStackTrace();
			}
			break; 
		case AUTH_SENT: // initiator
			try {
				// sw.printDeltaTime("Initiator recvAuthMsg");
				// Verify the remote certificate from AuthMsg
				AuthData authData = new AuthData(autEncRecv.decrypt(msg.getEData()));
                remCert = X509PKC.getCert(authData.getCert());
				// Verify the digital signature
                success = verifyAuth(authData.getAuth()); 
				if (success) { 
					Utils.trace("[KeyEx: "+locId+"] Successful verification of " + remId + "'s authenticator (SIG)\n" 
							+ "  Successful authentication: remote user is " + remId);
					state = AkeState.ESTABLISHED; // AuthMsg received and sent, success
					// sw.printElapsedTime("Initiator total duration");
					Utils.trace("[KeyEx: "+locId+"] Initiator: Auth handshake done, state " 
							+ state + ". Success");
					//AuthMsg with early data
					ptxt =  authData.getData();
					Utils.trace("[KeyEx: "+locId+"] Received early data: " + new String(ptxt)); 
					notifyTerminate(); 
				}
				else { // Reject. Terminate. 
					Utils.trace("[KeyEx: "+locId+"] Failed authentication of " + remId); 
					sendFailMsg(remId, "Initiator: Key exchange failed"); // -> state=FAILED
				}
			}
			catch (Exception e) { 
				System.out.println("[KeyEx: "+locId + "]: Initiator (recv AuthMsg). Key exchange failed (exception)"); 
				sendFailMsg(remId, "Initiator: Key exchange failed"); // -> state=FAILED
				e.printStackTrace();
			}
			break; 
		case ESTABLISHED: // terminated + success
			break; // ignore (abort?)
		case FAILED: // terminated + fail
			break; // ignore
		default: // abort: send FailMsg and terminate + fail
			sendFailMsg(remId, "[KeyEx: "+locId+"] Illegal state " + state); // -> state=FAILED
		}
		return null;
	}
	
	/* Not used in 4-message variant */
	public byte[] recvInitAuthMsg(InitAuthMsg msg) throws Exception
	{
		sendFailMsg(remId, "[KeyEx: "+locId+"] Illegal message " + state); // -> state=FAILED
		return null; 
	}	
	
	/**
	 * Generates local protocol fresh values:
	 * - random local nonce
	 * - local ephemeral DH key pair
	 */
	
	private void generateNonceAndDHKeys() throws Exception
	{
		SecureRandom rand=new SecureRandom();
		locNonce= new byte[nonceLen/8];
		rand.nextBytes(locNonce);
		locDHKeyPair=KeyAgrDH.genDHKeyPair(commonCrypto.getDhName(), commonCrypto.getDhKeyLen());
		KeyAgrDH.printDHPublicKey("[KeyEx: "+locId+"] DH public key:/n", locDHKeyPair.getPublic());
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
	        boolean isGCM = (commonCrypto.getEncSecName().split("/")[1].equals("GCM"));
	        int randBytesLen = ((isGCM)? 4 : 6) * keyLen; // 2 + 2; 4 + 2
	        String macName = commonCrypto.getAutSecName();
	        // Compute DH shared secret
	        String dhName = commonCrypto.getDhName();
	        byte[] secretBytesDH = KeyAgrDH.genDHSecret(dhName, locDHKeyPair, remDHPubBytes);
	        GenSessionKeyBytes genKeyBytes = new GenSessionKeyBytes(macName);
	        byte[] seed = (initiator)?
	                Utils.concatenate(locNonce, remNonce): // initiator
	                Utils.concatenate(remNonce, locNonce); // responder
	        // The PRF for key derivation is the selected MAC scheme
	        SecretKey kdk = genKeyBytes.extract(secretBytesDH, seed);
	        byte[] randBytes = genKeyBytes.expand(kdk, seed, randBytesLen);
	        // Keys for local/remote authenticator and for data send/receive
	        byte[] authRandBytes = new byte[2 * keyLen];
	        byte[] dataRandBytes = new byte[randBytesLen - 2 * keyLen];
	        Utils.split(randBytes, authRandBytes, dataRandBytes);
	        byte[][] authKeyBytes = new byte[2][keyLen];
	        Utils.split(authRandBytes, authKeyBytes);
	        locKeyAuth = new SecretKeySpec(authKeyBytes[initiator? 0 : 1], macName);
	        remKeyAuth = new SecretKeySpec(authKeyBytes[initiator? 1 : 0], macName);
	        setSessionKeys(dataRandBytes);
	    }
	 

	 /**
		 * Recomputes MAC(remId) with the remote authentication session key.
		 */
		private byte[] verifyIdMac() throws Exception
		{
			AutSec authSec = new AutSec(commonCrypto.getAutSecName());
			authSec.setKey(remKeyAuth);
			return authSec.genMac(remId.getBytes());
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
				throw new Exception("[KeyEx: "+locId+"] Invalid Certificate: Wrong Subject name");
			}
		}
	 
}

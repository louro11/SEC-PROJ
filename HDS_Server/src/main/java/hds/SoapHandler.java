package hds;

import static javax.xml.bind.DatatypeConverter.parseBase64Binary;
import static javax.xml.bind.DatatypeConverter.printBase64Binary;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Iterator;
import java.util.Set;

import javax.xml.namespace.QName;
import javax.xml.soap.Name;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPHeaderElement;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.w3c.dom.DOMException;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

//import pt.upa.ca.ws.CertificateException_Exception;
//import pt.upa.ca.ws.IOException_Exception;
//import pt.upa.ca.ws.cli.CAClient;
//import pt.upa.transporter.ws.Nonce;
//import java.security.cert.Certificate;
//import java.security.cert.CertificateException;
//import java.security.cert.CertificateFactory;


public class SoapHandler implements SOAPHandler<SOAPMessageContext> {
	
	public static final String CLASS_NAME = SoapHandler.class.getSimpleName();
	public static final String ENTITY_PROPERTY = "senderToPut";
	public static final String SENDER_HEADER = "senderName";
	public static final String SENDER_NS = "urn:senderNameNS";
	public static final String SIGNATURE_HEADER = "signature";
	public static final String SIGNATURE_NS = "urn:signatureNS";
	public static final String NONCE_CONTENT = "nonceToPut";
	public static final String NONCE_HEADER = "nonce";
	public static final String NONCE_NS = "urn:nonceNS";
	
	//Passwords generated from script
	private final static String KEY_PASS = "1nsecure";
	private final static String STORE_PASS = "ins3cur3";
	private final static String CA_CERTIFICATE_PASS = "1ns3cur3";

	// CA Client instance, 9090 is UDDI's port
	//CAClient CA = new CAClient("http://localhost:9090", "UpaCA");

	
    public boolean handleMessage(SOAPMessageContext smc) {
		
    	// Check message direction
    	Boolean outbound = (Boolean) smc.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
		
    	if (outbound) {
			
    		
				System.out.println(  "\n\n############################");
				System.out.println(  "#          Outbound        #");
				System.out.println(  "#        SOAP  Message     #");
				System.out.println(  "############################");
				System.out.println("  • Message number: "+ Nonce.getInstance().getCount());
					
				try {
					// Add header with username 
					String header = putServerNameHeader(smc); //ATENCAO HEADER PODE SER NULL (RETURN DO CATCH NO putCompanyHeader(smc), PENSAR E ARRANJAR)!	
					
					// Save message changes
					smc.getMessage().saveChanges();
					
					// Add header with Nonce
					putNonceHeader(smc);
					
					// Save message changes
					smc.getMessage().saveChanges();
					
					// Get my Private Key from KeyStore
					PrivateKey privateKey = getServerPrivateKey();

					// Prepare content to be signed (Body + Username Header + Nonce Header)
					String message = getSoapString(smc);
					
					// Get the signature of the message = (PK[Digest])
					byte[] signature = makeDigitalSignature(message.getBytes(), privateKey);
					
					// Add header with signature
					putSignatureHeader(smc, signature);
					
					// Save message changes
					smc.getMessage().saveChanges();	
					
					// Print message
		        	System.out.println("  • Final SOAP message to be sent: ");
		            smc.getMessage().writeTo(System.out);
					System.out.println("\n\n\n");
					
			    
				} catch (Exception e) {
					e.printStackTrace();
					// TRATAR E VER SE PODEMOS ESPECIFICAR A EXCEPTION
					// THROW NEW RUNTIMEEXCEPTION("...");
				}
		}	

		else{
			System.out.println(  "############################");
			System.out.println(  "#           Inbound        #");
			System.out.println(  "#        SOAP  Message     #");
			System.out.println(  "############################");
			System.out.println("  • Message number: "+ Nonce.getInstance().getCount());
			
			try {
				
				// Get name of the received message sender from Header
				String headerValue = getSenderUsernameHeader(smc); //ATENCAO HEADER PODE SER NULL (RETURN DO CATCH NO putCompanyHeader(smc), PENSAR E ARRANJAR)!

				// Get Nonce of the received message from Header
				long nonce = getNonceHeader(smc);
				
				// Prepare content of message to verify (Body + Header + Nonce) 
				boolean v;
				byte[] digest = getDigest(smc);
				
				SOAPEnvelope se = getSoapEnvelope(smc);
				Name digestName = se.createName(SIGNATURE_HEADER, "H", SIGNATURE_NS);	
				Node nodeToRemove = null;
				NodeList nl = smc.getMessage().getSOAPHeader().getChildNodes();
				for(int i = 0; i < nl.getLength(); i++){
					if(nl.item(i).getNodeName().equals(digestName.getQualifiedName())){
						nodeToRemove = nl.item(i);
					}
				}
						
				smc.getMessage().getSOAPHeader().removeChild(nodeToRemove);
				smc.getMessage().saveChanges();
				String message = getSoapString(smc);
				
				System.out.println("  • Message to be verified with " + headerValue + "'s PublicKey: ");
				smc.getMessage().writeTo(System.out);

				
	            // Verify signature
				System.out.println(System.getProperty("user.dir"));
				PublicKey pubKey = getPublicKeyUsername(headerValue, "../keys/");
				
				if(!(v = verifyDigitalSignature(digest, message.getBytes(), pubKey)))
					throw new RuntimeException();
				if(Nonce.getInstance().checkinboundNonce(headerValue, nonce))
					throw new RuntimeException();
				
				
				String method = smc.getMessage().getSOAPBody().getFirstChild().getLocalName();
				
				switch(method){
				
					case "register":
						if(!validPublicKeyFromArgument(smc, pubKey))
							throw new RuntimeException();
						break;
						
					case "send_amount":
						if(!validPublicKeyFromArgument(smc, pubKey))
							throw new RuntimeException();
						break;
						
					case "check_account":
						if(!validPublicKeyFromArgument(smc, pubKey))
							throw new RuntimeException();
						break;
						
					case "receive_amount":
						if(!validPublicKeyFromArgument(smc, pubKey))
							throw new RuntimeException();
						break;
						
					default:
						break;
				}
				
				return true;
				

			} catch (SOAPException e) {
				System.out.printf("Inbound message Transporter-WS-Client Failed to get SOAP header because of %s%n", e);
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidKeySpecException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
    	return true;
    }
    
    private boolean validPublicKeyFromArgument(SOAPMessageContext smc, PublicKey pubKey) throws DOMException, SOAPException{
    	String argKeyRA = smc.getMessage().getSOAPBody().getFirstChild().getFirstChild().getTextContent();
		PublicKey argPubKeyRA = StringToPubliKey(argKeyRA);
		if(!argPubKeyRA.equals(pubKey))
			return false;
		else
			return true;
    }

    
    // Adds header with company identification to the message
    private String putCompanyHeader(SOAPMessageContext smc){
		
    	// Get String with identification from request context
		String propertyValue = (String) smc.get(ENTITY_PROPERTY);
		if(propertyValue==null)
			System.out.println("CONA CONA");

		// Put String in request SOAP header
		try {
			// Get SOAP envelope
			SOAPMessage msg = smc.getMessage();
			SOAPPart sp = msg.getSOAPPart();
			SOAPEnvelope se = sp.getEnvelope();

			// Add header
			SOAPHeader sh = se.getHeader();
			if (sh == null)
				sh = se.addHeader();

			// Add header element (name, namespace prefix, namespace)
			Name name = se.createName(SENDER_HEADER, "H", SENDER_NS);
			SOAPHeaderElement element = sh.addHeaderElement(name);

			// Add header element value
			String newValue = propertyValue;
			element.addTextNode(newValue);

			// Print header
			System.out.println("  • Added Header with my identification: "+ newValue);
			
			return newValue;

		} catch (SOAPException e) {
			System.out.printf("Outbound message - Failed to add SOAP header because of %s%n", e);
			System.err.println((e.getMessage()));
			return null;
		}
    }
    
    // Adds header with unique nonce to the message    
	private void putNonceHeader(SOAPMessageContext smc) {
		
		// Get String from request context
		long propertyValue = (long) smc.get(NONCE_CONTENT);

		// Put String in SOAP header
		try {
			// Get SOAP envelope
			SOAPMessage msg = smc.getMessage();
			SOAPPart sp = msg.getSOAPPart();
			SOAPEnvelope se = sp.getEnvelope();

			// Add header
			SOAPHeader sh = se.getHeader();
			if (sh == null)
				sh = se.addHeader();

			// Add header element (name, namespace prefix, namespace)
			Name name = se.createName(NONCE_HEADER, "H", NONCE_NS);
			SOAPHeaderElement element = sh.addHeaderElement(name);

			// Add header element value
			long newValue = propertyValue;
			element.addTextNode(Long.toString(newValue));

			// Print header
			System.out.println("  • Added Header with Nonce: "+ newValue);

		} catch (SOAPException e) {
			System.out.printf("Outbound message Transporter-WS-Client Failed to add SOAP header because of %s%n", e);
			System.err.println((e.getMessage()));
		}
		
	}

	// Returns String of the whole message
	private String getSoapString(SOAPMessageContext smc) throws SOAPException, IOException{

    	ByteArrayOutputStream stream = new ByteArrayOutputStream();
    	smc.getMessage().writeTo(stream);
    	return new String(stream.toByteArray(),"utf-8");
    }
		
    // Create signature and returns it
	private static byte[] makeDigitalSignature(byte[] bytes, PrivateKey privateKey) throws Exception {

		// get a signature object using the SHA-1 and RSA combo
		// and sign the plain-text with the private key
		Signature sig = Signature.getInstance("SHA1WithRSA");
		sig.initSign(privateKey);
		sig.update(bytes);
		byte[] signature = sig.sign();
		
		return signature;
	}

	// Returns Private Key from KeyStore
	private static PrivateKey getPrivateKeyFromKeystore(String keyStoreFilePath, char[] keyStorePassword, String keyAlias, char[] keyPassword) throws Exception {

		KeyStore keystore = readKeystoreFile(keyStoreFilePath, keyStorePassword);
		PrivateKey key = (PrivateKey) keystore.getKey(keyAlias, keyPassword);
		if (key != null) System.out.println("  • Got Private Key from KeyStore! ");
		return key;
	}

	// Reads KeyStore File
	private static KeyStore readKeystoreFile(String keyStoreFilePath, char[] keyStorePassword) throws Exception {
		
		System.out.println("  • Reading KeyStore... ");
		FileInputStream fis;
		try {
			fis = new FileInputStream(keyStoreFilePath);
		} catch (FileNotFoundException e) {
			System.err.println("Keystore file <" + keyStoreFilePath + "> not fount.");
			return null;
		}
		KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		keystore.load(fis, keyStorePassword);
		return keystore;
	}

    // Adds header with signature to the message
	private void putSignatureHeader(SOAPMessageContext smc, byte[] signature ) throws IOException{
    	
		// put token in request SOAP header
		try {
			
			// get SOAP envelope
			SOAPMessage msg = smc.getMessage();
			SOAPPart sp = msg.getSOAPPart();
			SOAPEnvelope se = sp.getEnvelope();

			// add header
			SOAPHeader sh = se.getHeader();
			
			if (sh == null)
				sh = se.addHeader();

			// add header element (name, namespace prefix, namespace)
			Name digestName = se.createName(SIGNATURE_HEADER, "H", SIGNATURE_NS);
			SOAPHeaderElement element = sh.addHeaderElement(digestName);
			
			// add header element value
			element.addTextNode(printBase64Binary(signature));
			
			// print header
			System.out.println("  • Added Header with signature and length in byte[]: " + signature.length);
			
		} catch (SOAPException e) {
			System.out.printf("Outbound message Transporter-WS-Client Failed to add SOAP header because of %s%n", e);
		}
		
    }

	private String getSenderUsernameHeader(SOAPMessageContext smc) throws SOAPException {
		
		SOAPEnvelope se = getSoapEnvelope(smc);
		SOAPHeader sh = getSoapHeader(smc);

		// check header
		if (sh == null) {
			System.out.println("Inbound message Transporter-WS-Client Header not found.");
			return null;
		}

		// get first header element
		Name name = se.createName(SENDER_HEADER, "H", SENDER_NS);
		Iterator it = sh.getChildElements(name);
		
		// check header element
		if (!it.hasNext()) {
			System.out.printf("xaxaxaxaxaxaxaxaInbound message Transporter-WS-Client Header element %s not found.%n", SENDER_HEADER);
			return null;
		}
		SOAPElement element = (SOAPElement) it.next();

		// get header element value
		String headerValue = element.getValue();
		System.out.println("  • Message from: " + headerValue);

		return headerValue;
	}

	private long getNonceHeader(SOAPMessageContext smc) throws SOAPException {
		SOAPEnvelope se = getSoapEnvelope(smc);
		SOAPHeader sh = getSoapHeader(smc);

		// check header
		if (sh == null) {
			System.out.println("Inbound message: Nonce Header not found.");
			return 0;
		}

		// get first header element
		Name name = se.createName(NONCE_HEADER, "H", NONCE_NS);
		Iterator it = sh.getChildElements(name);
		
		// check header element
		if (!it.hasNext()) {
			System.out.printf("xaxaxaxaxaxaxaxaInbound message Transporter-WS-Client Header element %s not found.%n", SENDER_HEADER);
			return 0;
		}
		SOAPElement element = (SOAPElement) it.next();

		// get header element value
		String headerValue = element.getValue();
		long nonce = Long.valueOf(headerValue).longValue();
		System.out.println("  • Got Nonce: " + headerValue);

		return nonce;
	}





    
	private byte[] getDigest(SOAPMessageContext smc) throws SOAPException{
		SOAPEnvelope se = getSoapEnvelope(smc);
		SOAPHeader sh = getSoapHeader(smc);

		// check header
		if (sh == null) {
			System.out.println("Inbound message: Header not found.");
			return null;
		}

		// get first header element
		Name name = se.createName(SIGNATURE_HEADER, "H", SIGNATURE_NS);
		Iterator it = sh.getChildElements(name);
		
		// check header element
		if (!it.hasNext()) {
			System.out.printf("Inbound message Header element %s not found.%n", SENDER_HEADER);
			return null;
		}
		SOAPElement element = (SOAPElement) it.next();

		// get header element value
		String headerValue = element.getValue();
				
		// print header
		System.out.println("  • Got Header with signature and length in byte[]: " + 		parseBase64Binary(headerValue).length
);
		return parseBase64Binary(headerValue);

	}
    
	private SOAPEnvelope getSoapEnvelope(SOAPMessageContext smc) throws SOAPException {
    	SOAPMessage msg = smc.getMessage();
		SOAPPart sp = msg.getSOAPPart();
		return sp.getEnvelope();
	}
	
	private SOAPHeader getSoapHeader(SOAPMessageContext smc) throws SOAPException {
		return getSoapEnvelope(smc).getHeader();
	}
	
	private static boolean verifyDigitalSignature(byte[] cipherDigest, byte[] bytes, PublicKey publicKey)
			throws Exception {

		//System.out.println("##### INSIDE VERIFY DIGITAL SIGNATURE: #####");
		//System.out.println("cipherDigest: " + printBase64Binary(cipherDigest));
		//System.out.println("bytes: " + printBase64Binary(bytes));

		boolean verification = false;
		// verify the signature with the public key
		System.out.println("\n  • Verifying signature...");

		Signature sig = Signature.getInstance("SHA1WithRSA");
		sig.initVerify(publicKey);
		sig.update(bytes);
		try {
			verification = sig.verify(cipherDigest);
			if (verification) System.out.println("  • Signature successfully verified!");
			if (!verification) System.out.println("  • Signature doesn't match! Be careful, there is a Man in the Middle around...");
			return verification;
		} catch (SignatureException se) {
			System.err.println("Caught exception while verifying signature " + se);
			return false;
		}
	}
	
	// Interface method
	public boolean handleFault(SOAPMessageContext smc) {
		return handleMessage(smc);
    }
	
	// Interface method
	@Override
    public void close(MessageContext messageContext) {
    }
    
	// Interface method
	@Override
	public Set<QName> getHeaders() {
		return null;
	}
	
	// Returns Private Key from KeyStore
	private static PublicKey getPublicKeyUsername(String username, String pathToKeystore) {
		try {
			File privKeyFile = new File(pathToKeystore + username + "_PublicKey");
			Charset charset = Charset.forName("UTF-8");
			BufferedReader reader = Files.newBufferedReader(privKeyFile.toPath(), charset);
			String key = reader.readLine();
			byte[] encoded = parseBase64Binary(key);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePublic(new X509EncodedKeySpec(encoded));
		} catch (Exception e) {
			e.printStackTrace();
			return null; 
		} 
	}
	
	// Adds header with company identification to the message
    private String putServerNameHeader(SOAPMessageContext smc){

		System.out.println("smc");
		System.out.println(smc);
		System.out.println("");
		
    	// Get String with identification from request context
		String propertyValue = (String) smc.get(ENTITY_PROPERTY);
		System.out.println("propertyValue");
		System.out.println(propertyValue);
		System.out.println("");
		// Put String in request SOAP header
		try {
			// Get SOAP envelope
			SOAPMessage msg = smc.getMessage();
			SOAPPart sp = msg.getSOAPPart();
			SOAPEnvelope se = sp.getEnvelope();
			System.out.println("msg");
			System.out.println(msg);
			System.out.println("");
			System.out.println("sp");
			System.out.println(sp);
			System.out.println("");
			System.out.println("se");
			System.out.println(se);
			System.out.println("");

			// Add header
			SOAPHeader sh = se.getHeader();
			if (sh == null)
				sh = se.addHeader();

			// Add header element (name, namespace prefix, namespace)
			Name name = se.createName(SENDER_HEADER, "H", SENDER_NS);
			SOAPHeaderElement element = sh.addHeaderElement(name);
			System.out.println("element");
			System.out.println(element);
			System.out.println("");
			// Add header element value
			String newValue = propertyValue;
			element.addTextNode(newValue);

			// Print header
			System.out.println("  • Added Header with my username: "+ newValue);
			
			return newValue;

		} catch (SOAPException e) {
			System.out.printf("Outbound message - Failed to add SOAP header because of %s%n", e);
			System.err.println((e.getMessage()));
			return null;
		}

    }
    
    
    // Returns Private Key from KeyStore
 	private static PrivateKey getServerPrivateKey() {
 		try {
 			File privKeyFile = new File("./HDS_SERVER_PrivateKey");
 			Charset charset = Charset.forName("UTF-8");
 			BufferedReader reader = Files.newBufferedReader(privKeyFile.toPath(), charset);
 			String key = reader.readLine();
 			byte[] encoded = parseBase64Binary(key);
 			KeyFactory kf = KeyFactory.getInstance("RSA");
 			return kf.generatePrivate(new PKCS8EncodedKeySpec(encoded));
 		} catch (Exception e) {
 			e.printStackTrace();
 			return null; 
 		} 
 	}
 	
	private PublicKey StringToPubliKey(String keyS) {
		try{
			byte[] publicBytes = convertStringToByteArray(keyS);
			return convertByteArrayToPubKey(publicBytes, "RSA");
		}catch(Exception e){
			return null;
		}
	}
	
	public static byte[] convertStringToByteArray(String string) throws Exception {
		return parseBase64Binary(string);
	}
	
	public static PublicKey convertByteArrayToPubKey(byte publicKeyBytes[], String algorithm) throws Exception {
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
	}
}

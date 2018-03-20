package hds;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.jws.HandlerChain;
import javax.jws.WebService;
import static javax.xml.bind.DatatypeConverter.parseBase64Binary;


@WebService(endpointInterface = "hds.HDSServer")
//@HandlerChain(file="handler-chain.xml")
public class HDSServerImpl implements HDSServer{
	private Map<PublicKey, Account> accounts = new HashMap<PublicKey, Account>();
	private ArrayList<Transfer> transfers = new ArrayList<Transfer>();
	private int transferCounter = 0;

	@Override
	public void register(String keyS, String username) throws InvalidInputException {
		System.out.println("REGISTER: " + username + " \tPUBLICKEY: " + keyS);
		
		if(username == null || !verifyPublicKey(keyS))
			throw new InvalidInputException("USERNAME OR PUBLICKEY NOT VALID");
		
		if(!username.matches("[A-Za-z0-9]+"))
			throw new InvalidInputException("USERNAME NEEDS TO BE ALPHANUMERIC");

		PublicKey key = StringToPubliKey(keyS);
		Account createdAccount = new Account(key, username);
		if(accountExists(createdAccount.getKey()) || usernameExists(username))
			throw new InvalidInputException("ACCOUNT ALREADY EXISTS"); //Lança excepção que o cliente apanha e imprime mensagem
		else
			accounts.put(key, createdAccount);
		
	}

	@Override
	public void send_amount(String sourceS, String destinationS, float amount) throws InvalidInputException {
		System.out.println("SEND: " + amount + " \tFROM: " + sourceS + " \tTO" + destinationS);
		PublicKey source = StringToPubliKey(sourceS);
		PublicKey destination = StringToPubliKey(destinationS);
		if(accountExists(source) && accountExists(destination)){
			Account sender = accounts.get(source);
			if(sender.getBalance()-amount >= 0){
				Account destinatary = accounts.get(destination);
				Transfer transfer = new Transfer(sender, destinatary, amount, transferCounter);
				transferCounter++;
				transfers.add(transfer);
				sender.sendCoins(transfer);
				destinatary.notifyTransfer(transfer);
			}
			else
				throw new InvalidInputException("INSUFFICIENT FUNDS");
				
		}
		else
			throw new InvalidInputException("SENDER OR DESTINATARY NOT REGISTERED YET");
	}

	@Override
	public void receive_amount(String keyS, int id) throws InvalidInputException {
		System.out.println(keyS + "\tACCEPT: " + id);
		PublicKey key = StringToPubliKey(keyS);
		if(id < transferCounter && !transfers.isEmpty()){
			Transfer transfer = this.getTransfers().get(id);
			if(accountExists(key)){
				Account destinatary = transfer.getDestinatary();
				if(destinatary.getKey().equals(key)){
					Account sender = transfer.getSender();
					if(transfer.getStatus().name().equals("PENDING")){
						destinatary.acceptTransfer(transfer);
						sender.acceptedTransfer(transfer);
					}
					else
						throw new InvalidInputException("TRANSFER WAS ALREADY ACCEPTED"); //Lança excepção que o cliente apanha e imprime mensagem
				}
				else
					throw new InvalidInputException("NO PERMISSION TO ACCEPT TRANSFER"); //Lança excepção que o cliente apanha e imprime mensagem
			}
			else
				throw new InvalidInputException("ACCOUNT NOT REGISTERED YET"); //Lança excepção que o cliente apanha e imprime mensagem	
		}
		else
			throw new InvalidInputException("UNKOWN TRANSFER ID"); //Lança excepção que o cliente apanha e imprime mensagem	
		
	}

	@Override
	public CheckResult check_account(String keyS) {
		System.out.println("CHECK ACCOUNT " + keyS);
		PublicKey key = StringToPubliKey(keyS);
		Account checkerAccount = accounts.get(key);
		return new CheckResult(checkerAccount.getBalance(), checkerAccount.getTransfersIn());
	}

	@Override
	public AuditResult audit(String keyS) {
		System.out.println("AUDIT ACCOUNT " + keyS);
		PublicKey key = StringToPubliKey(keyS);
		Account checkerAccount = accounts.get(key);
		return new AuditResult(checkerAccount.getTransfersHistory());
	}

	public boolean accountExists(PublicKey key){
		if(accounts.get(key) == null){
			return false;
		}
		else
			return true;
	}

	public ArrayList<Transfer> getTransfers() {
		return transfers;
	}
	
	private boolean usernameExists(String username) {
		boolean found = false;
		for (Map.Entry<PublicKey, Account> entry : accounts.entrySet()){
			if(entry.getValue().getUsername().equals(username)){
				found = true;
			}
		}
		return found;
	}
	
	public static byte[] convertStringToByteArray(String string) throws Exception {
		return parseBase64Binary(string);
	}
	
	public static PublicKey convertByteArrayToPubKey(byte publicKeyBytes[], String algorithm) throws Exception {
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
	}
	
	private PublicKey StringToPubliKey(String keyS) {
		try{
			byte[] publicBytes = convertStringToByteArray(keyS);
			return convertByteArrayToPubKey(publicBytes, "RSA");
		}catch(Exception e){
			return null;
		}
	}
	
	private boolean verifyPublicKey(String keyS){
		if(keyS == null)
			return false;
		if(StringToPubliKey(keyS)==null)
			return false;
		return true;
	}

}

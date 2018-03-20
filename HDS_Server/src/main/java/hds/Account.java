package hds;

import java.security.PublicKey;
import java.util.ArrayList;

public class Account {
	
	private PublicKey key;
	private float balance;
	private float initialWalletValue = 500;
	private String username;
	private ArrayList<Transfer> transfersIn = new ArrayList<Transfer>();
	private ArrayList<Transfer> transfersOut = new ArrayList<Transfer>();
	private ArrayList<Transfer> transfersHistory = new ArrayList<Transfer>();

	public Account(PublicKey key, String username){
		this.key = key;
		this.balance = initialWalletValue;
		this.username = username;
	}
	
	public float getBalance() {
		return balance;
	}

	public float getInitialWalletValue() {
		return initialWalletValue;
	}

	public PublicKey getKey() {
		return key;
	}

	public ArrayList<Transfer> getTransfersIn() {
		return transfersIn;
	}

	public ArrayList<Transfer> getTransfersOut() {
		return transfersOut;
	}
	
	public void sendCoins(Transfer transfer){
		transfersOut.add(transfer);
		transfersHistory.add(transfer);
		this.balance = this.balance - transfer.getValue();
	}
	
	public void notifyTransfer(Transfer transfer){
		transfersIn.add(transfer);
	}
	
	public void acceptedTransfer(Transfer transfer) throws InvalidInputException{
		Account sender = transfer.getSender();
		Account destinatary = transfer.getDestinatary();
		float value = transfer.getValue();
		int OutSize = transfersOut.size()-1;
		boolean found = false;
		for(int i = 0; i <= OutSize; i++){
		    Transfer t = transfersOut.get(i);
		    if(t.getDestinatary() == destinatary && t.getSender() == sender && t.getValue() == value){
		    	transfersOut.remove(i);
		    	found = true;
		        break;
		    }
		}
		if(!found)
			throw new InvalidInputException("ERRO (o receiver aceitou uma transferencia que nao esta registada no sender)"); //Lança excepção que o cliente apanha e imprime mensagem
	}
	
	public void acceptTransfer(Transfer transfer) throws InvalidInputException{
		Account sender = transfer.getSender();
		Account destinatary = transfer.getDestinatary();
		float value = transfer.getValue();
		int OutSize = transfersIn.size()-1;
		boolean found = false;
		for(int i = 0; i <= OutSize; i++){
		    Transfer t = transfersIn.get(i);
		    if(t.getDestinatary() == destinatary && t.getSender() == sender && t.getValue() == value){
		    	transfersIn.remove(i);
		    	this.balance = this.balance + transfer.getValue();
		    	transfer.accept();
		    	transfersHistory.add(transfer);
		    	found = true;
		        break;
		    }
		}
		if(!found)
			throw new InvalidInputException("ERRO (o receiver aceitou uma transferencia que nao esta registada no receiver)"); //Lança excepção que o cliente apanha e imprime mensagem
	}
	

	public ArrayList<Transfer> getTransfersHistory() {
		return transfersHistory;
	}

	public String getUsername() {
		return username;
	}

}

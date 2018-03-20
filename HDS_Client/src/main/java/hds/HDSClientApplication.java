package hds;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Scanner;

public class HDSClientApplication {
	
	public static void main (String[] args){
		
		String pathToKeystore = "../../../../keys/";
	
		HDSServerImplService hdsService = new HDSServerImplService();
		HDSServer hds = hdsService.getPort(HDSServer.class);
		
		try{
			//Só INTERESSA PARA PODER FA>ER A ESTRUTURA DO MENU, QUNDO AS COISA ESTIVEREM REMOTAS NAO VAI SER PRECISO ESTAS CENAS
			KeyPairGenerator keyGen1 = KeyPairGenerator.getInstance("RSA");
	        keyGen1.initialize(1024);
	        KeyPair keypair1 = keyGen1.genKeyPair();
	        PublicKey pubKey = keypair1.getPublic();
	        byte[] keyP = pubKey.getEncoded();
	        String key = Base64.getEncoder().encodeToString(keyP);
			Scanner scanner = new Scanner(System.in);
			boolean quit = false;
			while(!quit){
				printMenu();
			    String choiceS = scanner.next();
			    int choice = -1;
			    
			    try{
			    	choice = Integer.parseInt(choiceS);
		    	}catch(NumberFormatException e){
		    		System.out.println("Ups. Invalid option...");
		    		System.out.println("Please try again (1, 2, 3 , 4, 5 or 0)");
		    		continue;
		    	}
		
			    switch (choice) {
			        case 1:
			        	System.out.println("SELECT A USERNAME: *type 'BACK' to navigate to the previous menu.");
			        	boolean usernameGiven = false;
			        	String username = null;
					    while(!usernameGiven){
					    	username = scanner.next();
					    	if(username.equals("BACK") || username.equals("back"))
						    	break;
					    	else
					    		usernameGiven = true;
					    }
			        	if(!usernameGiven)
			        		break;
			        	try{
			        		hds.register(key, username);
			        		putKeyInKeyStore(keyP, username, pathToKeystore);
			        		break;
			        	}catch(InvalidInputException_Exception e){
			    	    	System.out.println("#############################");
			    	    	System.out.println("");
			    	    	System.out.println(e.getMessage());
			    	    	System.out.println("");
			    	    	System.out.println("#############################");
			    	    	break;	
		    	    	}
			            
			        case 2:
			    		System.out.println("SELECT DESTINATARY: *type 'BACK' to navigate to the previous menu.");
			    		String username2 = scanner.next();
			    		if(username2.equals("BACK") || username2.equals("back"))
			    			break;
			    		System.out.println("SELECT AMOUNT: *type 'BACK' to navigate to the previous menu.");
			    		int amount = -1;
			    		boolean amountGiven = false;
			    	    while(!amountGiven){
			    	    	String amountS = scanner.next();
			    	    	if(amountS.equals("BACK") || amountS.equals("back"))
			    		    	break;
			    	    	try{
			    	    		amount = Integer.parseInt(amountS);
			    	    		amountGiven = true;
			    	    	}catch(NumberFormatException e){
			    	    		System.out.println("Ups. Invalid amount...");
			    	    		System.out.println("Please try again (amount is an integer number)");
			    	    		continue;
			    	    	}
			    	    }
			    	    try{
			    	    	hds.sendAmount(key, getKeyFromUsername(username2, pathToKeystore), amount);
			    	    	break;
			    	    }catch(InvalidInputException_Exception e){
			    	    	System.out.println("#############################");
			    	    	System.out.println("");
			    	    	System.out.println(e.getMessage());
			    	    	System.out.println("");
			    	    	System.out.println("#############################");
			    	    	break;	
			    	    }
			            
			        case 3:
			        	CheckResult response = hds.checkAccount(key);
			        	printCheckResult(response);
			        	pressAnyKeyToContinue();
			            break;
			            
			        case 4:
			        	System.out.println("SELECT TRANSFER ID: *type 'BACK' to navigate to the previous menu.");
			        	boolean idGiven = false;
			        	int id = -1;
					    while(!idGiven){
					    	String idS = scanner.next();
					    	if(idS.equals("BACK") || idS.equals("back"))
						    	break;
					    	try{
					    		id = Integer.parseInt(idS);
					    		idGiven = true;
					    	}catch(NumberFormatException e){
					    		System.out.println("Ups. Invalid transfer ID...");
					    		System.out.println("Please try again (ID is an integer number)");
					    		continue;
					    	}
					    }
					    try{
						    if(id!=-1){	
						    	hds.receiveAmount(key, id);
						    	pressAnyKeyToContinue();
				        	}
				            break;
					    }catch(InvalidInputException_Exception e){
			    	    	System.out.println("#############################");
			    	    	System.out.println("");
			    	    	System.out.println(e.getMessage());
			    	    	System.out.println("");
			    	    	System.out.println("#############################");
			    	    	break;	
			    	    }
			            
			        case 5:
			        	System.out.println("SELECT ACCOUNT TO AUDIT: *type 'BACK' to navigate to the previous menu.");
			    		String username5 = scanner.next();
			    		if(username5.equals("BACK") || username5.equals("back"))
			    			break;
			        	AuditResult auditResponse = hds.audit(getKeyFromUsername(username5, pathToKeystore));
			        	ArrayList<Transfer> history = (ArrayList<Transfer>) auditResponse.getTransfersHistory();
			        	if(history.isEmpty()){
			        		System.out.println("YOU HAVE NO TRANSFERS REGISTERED");
			        	}
			        	else{
			        		for (Transfer transfer : history) {
			        			printTransfer(transfer);
			        		}
			        	}
			        	pressAnyKeyToContinue();
			            break;
			            
			        case 0:
			        	scanner.close();
			        	quit = true;
			        	System.out.println("################");
			        	System.out.println("      Bye!      ");
			        	System.out.println("################");
			            break;
			            
			        default:
			        	System.out.println("PLEASE CHOOSE A VALID OPTION (1, 2, 3, 4, 5 or 0)");
			        	
			    }
			}
		}
		catch(Exception e){
			e.printStackTrace();
		}
	}
	
	private static void putKeyInKeyStore(byte[] publicBytes, String username, String pathToKeystore) {
		
		try {
			SavePemPublicKey(Base64.getEncoder().encodeToString(publicBytes), pathToKeystore + username + "_PublicKey");
		} catch (Exception e1) {
			e1.printStackTrace();
		}
	}
	
    public static  void  SavePemPublicKey(String key, String filename) throws Exception {
        File f = new File(filename);
        FileOutputStream fos = new FileOutputStream(f);
        DataOutputStream dos = new DataOutputStream(fos);
        dos.writeBytes(key);
        dos.flush();
        dos.close();
    }
	
	
	private static void printCheckResult(CheckResult response) {
    	ArrayList<Transfer> transfersIn = (ArrayList<Transfer>) response.getTransfersIn();
    	float balance = response.getBalance();
    	if(transfersIn.isEmpty()){
    		System.out.println("YOU HAVE NO TRANSFERS TO ACCEPT");
    	}
    	else{
    		for (Transfer transfer : transfersIn) {
    			printTransfer(transfer);
    		}
    	}
    	System.out.println("CURRENT ACCOUNT BALANCE: " + balance);
	}

	private static void printMenu() {
		System.out.println("");
		System.out.println("");
		System.out.println("");
		System.out.println("################################");
		System.out.println("          HDS PROJECT");
		System.out.println("################################");
		System.out.println("");
		System.out.println("SELECT AN OPTION");
		System.out.println("1 - REGISTER ACCOUNT");
		System.out.println("2 - TRANSFER MONEY");
		System.out.println("3 - CHECK ACCOUNT");
		System.out.println("4 - ACCEPT TRANSFER");
		System.out.println("5 - SEE TRANSACTION HISTORY");
		System.out.println("0 - EXIT");
		
	}
	
	private static void pressAnyKeyToContinue() { 
	        System.out.println("Press Enter key to continue...");
	        try
	        {
	            System.in.read();
	        }  
	        catch(Exception e)
	        {}  
	 }
	
	private static String getKeyFromUsername(String username, String pathToKeystore) {
		try {
			byte[] encoded = Files.readAllBytes(Paths.get(pathToKeystore + username + "_PublicKey"));
			return new String(encoded, "UTF-8");
		} catch (IOException e) {
			e.printStackTrace();
			return null; 
		} 
	}
	
	private static void printTransfer(Transfer transfer) {
		System.out.println("#############################################################");
		System.out.println(" ");
		System.out.println("ID: " + transfer.getId());
		System.out.println("SENDER: " + transfer.getUsernameSender());
		System.out.println("DESTINATARY: " + transfer.getUsernameDestinatary());
		System.out.println("AMOUNT: " + transfer.getValue());
		System.out.println("STATUS: " + transfer.getStatus());
		System.out.println("REQUEST TIME: " + transfer.getRequestTime());
		System.out.println(" ");
		System.out.println("#############################################################");
	}
}

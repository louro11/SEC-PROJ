package hds;

import java.util.List;

import javax.xml.ws.Binding;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.handler.Handler;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class CheckAccountTest {
	
	 static String keyS1 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCJZTyXjVttDI2gbqdAWShLpndoD/Wng68xR2nMvZ6H2Qor8ZDNnsAbXNCBpFZFUhp0ka0dt8M/L/uH/cFbDw8kn8U4d8gDJTLxwMtF6bQVkNDyoWixj5Ir+Kj5J7XSkX8sDzlTOahZ549URPX/8uaq6SfsQx2hTOJjnfuMp8r2EQIDAQAB";
	 static String keyS2 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDiCHFJagc67ZQZtCEXzZ19rE5kLW4n5geDB/0pDAx+2ZYlOfDsx91J2xE6UANJHmmPG4W9dhPN4J1R12ncFUZ2e6Qd3swA4vswwGbL9Sq+Fo/H3wOzwp15K1M6QjsEhx/JpcpToN35GTLjlgrE2t5loWFE3gL0pL6IYq0PQQLuaQIDAQAB";

	 
	 HDSServerImplService hdsService = new HDSServerImplService();
	 HDSServer hds = hdsService.getPort(HDSServer.class);
	
	 @BeforeClass
	    public static void oneTimeSetUp() throws FailToLogRequestException_Exception, InvalidInputException_Exception {
		    
	    }

	    @AfterClass
	    public static void oneTimeTearDown() {
	    }

	    // members
	   
	    // initialization and clean-up for each test
	    @Before
	    public void setUp() throws FailToLogRequestException_Exception, InvalidInputException_Exception { 
	    	System.out.println("hi");
	     	
	 		Binding binding = ((BindingProvider)hds).getBinding();
	 	    List<Handler> handlerList = binding.getHandlerChain();
	 	    handlerList.add(new SoapHandler());
	 	    binding.setHandlerChain(handlerList);
	 	   hds.register(keyS1, "testuser");
	 	    System.out.println("hi");
	    }

	    @After
	    public void tearDown() {
	    	
	    }
	    
	    
	    @Test
	    public void  ok() throws FailToLogRequestException_Exception, InvalidInputException_Exception {
	    	//hds.register(keyS1, "carlos2");
	    }
	    
	    @Test(expected = InvalidInputException_Exception.class) 
	    public void  usernameExists() throws FailToLogRequestException_Exception, InvalidInputException_Exception  {
	    	
	    	hds.register(keyS2, "testuser");
	    	
	    }
	    
}

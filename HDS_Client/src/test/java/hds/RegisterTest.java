package hds;

import org.junit.*;
import static org.junit.Assert.*;

import java.io.File;
import java.io.FileWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.List;

import javax.xml.ws.Binding;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.handler.Handler;

public class RegisterTest {

    // static members
	 static String keyS1 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCJZTyXjVttDI2gbqdAWShLpndoD/Wng68xR2nMvZ6H2Qor8ZDNnsAbXNCBpFZFUhp0ka0dt8M/L/uH/cFbDw8kn8U4d8gDJTLxwMtF6bQVkNDyoWixj5Ir+Kj5J7XSkX8sDzlTOahZ549URPX/8uaq6SfsQx2hTOJjnfuMp8r2EQIDAQAB";
	 static String keyS2 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDiCHFJagc67ZQZtCEXzZ19rE5kLW4n5geDB/0pDAx+2ZYlOfDsx91J2xE6UANJHmmPG4W9dhPN4J1R12ncFUZ2e6Qd3swA4vswwGbL9Sq+Fo/H3wOzwp15K1M6QjsEhx/JpcpToN35GTLjlgrE2t5loWFE3gL0pL6IYq0PQQLuaQIDAQAB";
	 
	 HDSServerImplService hdsService;
	 HDSServer hds ;

    // one-time initialization and clean-up

    @BeforeClass
    public static void oneTimeSetUp() throws FailToLogRequestException_Exception, InvalidInputException_Exception {
    	
    }

    @AfterClass
    public static void oneTimeTearDown() {
    }

    // members
   
    // initialization and clean-up for each test
    @Before
    public void setUp() throws FailToLogRequestException_Exception, InvalidInputException_Exception{
    	hdsService = new HDSServerImplService();
    	hds = hdsService.getPort(HDSServer.class);
    	Binding binding = ((BindingProvider)hds).getBinding();
	    List<Handler> handlerList = binding.getHandlerChain();
	    handlerList.add(new SoapHandler());
	    binding.setHandlerChain(handlerList);
	    hds.register(keyS1, "testuser");
	    System.out.println("finish register test setup");
    }

    @After
    public void tearDown() {
   
    }


    // tests
    @Test
    public void  ok() {
    	
    }
    
   @Test(expected = InvalidInputException_Exception.class) 
    public void  usernameExists() throws FailToLogRequestException_Exception, InvalidInputException_Exception  {
    	
    	hds.register(keyS2, "testuser");
    	
    }
   
    @Test(expected = InvalidInputException_Exception.class) 
    public void  keyExists() throws FailToLogRequestException_Exception, InvalidInputException_Exception {
    	hds.register(keyS1, "sec");	
    }
    
    
    @Test(expected = InvalidInputException_Exception.class) 
    public void  keyAndUsernameExist() throws FailToLogRequestException_Exception, InvalidInputException_Exception{
    	hds.register(keyS1, "testuser");
    }
    
    
    @Test(expected = InvalidInputException_Exception.class) 
    public void  nullKey() throws FailToLogRequestException_Exception, InvalidInputException_Exception{
    	hds.register(null, "sec");
    }

    
    @Test(expected = InvalidInputException_Exception.class) 
    public void  nullUsername() throws FailToLogRequestException_Exception, InvalidInputException_Exception {
    	hds.register(keyS2, null);
    }
    
    
    @Test(expected = InvalidInputException_Exception.class) 
    public void  nullKeyAndUsername() throws FailToLogRequestException_Exception, InvalidInputException_Exception {
    	hds.register(null, null);
    }

    
    @Test(expected = InvalidInputException_Exception.class) 
    public void  nonAlphaNumericUsername() throws FailToLogRequestException_Exception, InvalidInputException_Exception {
    	hds.register(keyS1, "12/dd$%");
    }
    
    
    @Test(expected = InvalidInputException_Exception.class) 
    public void  nonAlphaNumericUsername2() throws FailToLogRequestException_Exception, InvalidInputException_Exception {
    	hds.register(keyS1, "-1");
    }
    
    
    @Test(expected = InvalidInputException_Exception.class) 
    public void  falseKey() throws FailToLogRequestException_Exception, InvalidInputException_Exception  {
    	hds.register("ThisKeyIsFake", "sec1");
    }
    
    @Test
    public void  oddConstructor() {
//        assertEquals(13, upa1.getRegions().length);
//        assertEquals("UpaTransporter1", upa1.getCompanyName());
    }
}

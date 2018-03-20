//Interface Server
package hds;


import javax.jws.WebService;

import java.security.PublicKey;
import java.util.ArrayList;

import javax.jws.WebMethod;
import javax.jws.soap.SOAPBinding;
import javax.jws.soap.SOAPBinding.Style;

@WebService
@SOAPBinding(style = Style.RPC)
public interface HDSServer {
	@WebMethod void register(String key, String username) throws InvalidInputException;
	@WebMethod void send_amount(String source, String destination, float amount) throws InvalidInputException;
	@WebMethod void receive_amount(String key, int id) throws InvalidInputException;
	@WebMethod CheckResult check_account(String key);
	@WebMethod AuditResult audit(String key);
}
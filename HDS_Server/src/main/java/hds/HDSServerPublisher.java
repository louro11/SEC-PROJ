//Publicação do Server 
//Verificar WSDL em http://127.0.0.1:9878/hds?wsdl

package hds;

import javax.xml.ws.Endpoint;


public class HDSServerPublisher {

	public static void main(String[] args)
	{
		System.out.println("Servidor a iniciar...");
		try {
			Endpoint.publish("http://127.0.0.1:9878/hds",
			new HDSServerImpl());
		} catch (InvalidInputException e) {
			System.out.println("LOG FILE IS CORRUPTED");
		} catch (FailToLogRequestException e) {
			System.out.println("LOG FILE IS CORRUPTED");
		}
	}
}
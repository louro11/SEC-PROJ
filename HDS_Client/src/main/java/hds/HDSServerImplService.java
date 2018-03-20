
package hds;

import java.net.MalformedURLException;
import java.net.URL;
import javax.xml.namespace.QName;
import javax.xml.ws.Service;
import javax.xml.ws.WebEndpoint;
import javax.xml.ws.WebServiceClient;
import javax.xml.ws.WebServiceException;
import javax.xml.ws.WebServiceFeature;


/**
 * This class was generated by the JAX-WS RI.
 * JAX-WS RI 2.2.9-b130926.1035
 * Generated source version: 2.2
 * 
 */
@WebServiceClient(name = "HDSServerImplService", targetNamespace = "http://hds/", wsdlLocation = "http://127.0.0.1:9878/hds?wsdl")
public class HDSServerImplService
    extends Service
{

    private final static URL HDSSERVERIMPLSERVICE_WSDL_LOCATION;
    private final static WebServiceException HDSSERVERIMPLSERVICE_EXCEPTION;
    private final static QName HDSSERVERIMPLSERVICE_QNAME = new QName("http://hds/", "HDSServerImplService");

    static {
        URL url = null;
        WebServiceException e = null;
        try {
            url = new URL("http://127.0.0.1:9878/hds?wsdl");
        } catch (MalformedURLException ex) {
            e = new WebServiceException(ex);
        }
        HDSSERVERIMPLSERVICE_WSDL_LOCATION = url;
        HDSSERVERIMPLSERVICE_EXCEPTION = e;
    }

    public HDSServerImplService() {
        super(__getWsdlLocation(), HDSSERVERIMPLSERVICE_QNAME);
    }

    public HDSServerImplService(WebServiceFeature... features) {
        super(__getWsdlLocation(), HDSSERVERIMPLSERVICE_QNAME, features);
    }

    public HDSServerImplService(URL wsdlLocation) {
        super(wsdlLocation, HDSSERVERIMPLSERVICE_QNAME);
    }

    public HDSServerImplService(URL wsdlLocation, WebServiceFeature... features) {
        super(wsdlLocation, HDSSERVERIMPLSERVICE_QNAME, features);
    }

    public HDSServerImplService(URL wsdlLocation, QName serviceName) {
        super(wsdlLocation, serviceName);
    }

    public HDSServerImplService(URL wsdlLocation, QName serviceName, WebServiceFeature... features) {
        super(wsdlLocation, serviceName, features);
    }

    /**
     * 
     * @return
     *     returns HDSServer
     */
    @WebEndpoint(name = "HDSServerImplPort")
    public HDSServer getHDSServerImplPort() {
        return super.getPort(new QName("http://hds/", "HDSServerImplPort"), HDSServer.class);
    }

    /**
     * 
     * @param features
     *     A list of {@link javax.xml.ws.WebServiceFeature} to configure on the proxy.  Supported features not in the <code>features</code> parameter will have their default values.
     * @return
     *     returns HDSServer
     */
    @WebEndpoint(name = "HDSServerImplPort")
    public HDSServer getHDSServerImplPort(WebServiceFeature... features) {
        return super.getPort(new QName("http://hds/", "HDSServerImplPort"), HDSServer.class, features);
    }

    private static URL __getWsdlLocation() {
        if (HDSSERVERIMPLSERVICE_EXCEPTION!= null) {
            throw HDSSERVERIMPLSERVICE_EXCEPTION;
        }
        return HDSSERVERIMPLSERVICE_WSDL_LOCATION;
    }

}

/**
 * Last Modified by: $Author: srosset $
 * On: $Date: 2002-05-17 23:18:09 $
 */package safe.policyManager;

import org.cougaar.core.blackboard.BlackboardClient;
import org.cougaar.core.component.BindingSite;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.MessageTransportService;
import org.cougaar.core.mts.MessageTransportClient;
import org.cougaar.core.mts.Message;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.servlet.BaseServletComponent;
import org.cougaar.util.UnaryPredicate;

import kaos.core.kpat.tunnel.TunnelServlet;
import kaos.core.kpat.tunnel.iKAoSPolicyAdminTunnel;
import kaos.core.kpat.tunnel.PolicyAdminBridge;
import kaos.core.service.transport.CougaarMessageTransportService;
import kaos.core.service.util.CougaarLocator;

import java.util.*;
import javax.servlet.*;
import javax.agent.service.transport.MessageReceiver;
import javax.agent.service.transport.MessageSender;

import safe.util.*;


public class PolicyAdminServletComponent
    extends BaseServletComponent implements MessageTransportClient
{
    public PolicyAdminServletComponent()
    {
    }
   
    public void init()
    {
        // initialize the bridge class
        CougaarMessageTransportService cougaarMessageTransport = new CougaarMessageTransportService(_mts);
        try {
            MessageReceiver messageReceiver = cougaarMessageTransport.newMessageReceiver();
            CougaarLocator myLocator = new CougaarLocator(_agentId + "PolicyAdminServletComponent");
            messageReceiver.bindToLocalLocator(myLocator);
            
            String domainName = System.getProperty("org.cougaar.safe.domainName");
            if (domainName == null) {
                throw new NullPointerException("System property org.cougaar.safe.domainName is not set");
            }            
            MessageSender messageSender = cougaarMessageTransport.newMessageSender();
            CougaarLocator dmLocator = new CougaarLocator(domainName);
            messageSender.bindToRemoteLocator(dmLocator);
            _bridgeClass = new PolicyAdminBridge(messageSender,
                                                 messageReceiver);
        }
        catch (Exception xcp) {
            xcp.printStackTrace();
        }                
    }
    
    /**
     * create the servlet
     */
    protected Servlet createServlet()
    {
        return new CougaarServlet();
    }

    /**
     * Get the path for the Servlet's registration. 
     */
    protected String getPath()
    {
        return "/policyAdmin";
    }

    /**
     * Object should transition to the LOADED state. 
     */
    public void load() 
    {
        org.cougaar.core.plugin.PluginBindingSite pbs = (org.cougaar.core.plugin.PluginBindingSite) bindingSite;
        _agentId = pbs.getAgentIdentifier().toAddress();
        init();                           
        super.load();
    }
    
    /**
     * Capture the (optional) load-time parameters. 
     */
    public void setParameter(java.lang.Object o)
    {
    }

    /**
     * Called object should perform any cleanup operations and transition to the
     * UNLOADED state.
     */
    public void unload() 
    {
        super.unload();
    }
    
    public void setMessageTransportService (MessageTransportService mts)
    {
        _mts = mts;
    }

    // implement MessageTransportClient
    public void receiveMessage(Message m) {}
    public MessageAddress getMessageAddress() {return null;}
    
    /**
     * Private classes
     */    private class CougaarServlet extends TunnelServlet    {
        public Object _getNewInstance()
            throws ServletException        {
            return _bridgeClass;
        }            }
        
    /**
     * Private variables
     */
    private String _agentId;
    private MessageTransportService _mts;
    private iKAoSPolicyAdminTunnel _bridgeClass;
}

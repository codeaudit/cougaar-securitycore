package safe.guard;

//import org.cougaar.core.society.Message;
//import org.cougaar.core.society.MessageAddress;
//import org.cougaar.core.naming.NamingService;
//import org.cougaar.core.mts.MessageTransportService;
//import org.cougaar.core.mts.MessageTransportClient;
import javax.agent.service.transport.MessageListener;
import javax.agent.service.transport.MessageReceiver;
import javax.agent.service.transport.MessageSender;

//import javax.agent.message.AcrNode;
//import javax.agent.TransportMessage;
//import javax.agent.Payload;

import ri.message.TransportMessage;
import ri.message.Payload;
//import ri.message.JasAcrNode;
import ri.message.Envelope;

import kaos.core.enforcer.Enforcer;
import kaos.core.guard.*;
import kaos.core.message.KAoSAcrNode;
import kaos.core.service.directory.DefaultKAoSAgentDescription;
import kaos.core.service.directory.DefaultKAoSEntityDescription;
import kaos.core.service.transport.CougaarMessageTransportService;
import kaos.core.service.util.CougaarLocator;
import kaos.core.util.VMIDGenerator;
import kaos.core.util.MethodCallRequestMsg;
import kaos.core.util.MethodCallResultMsg;
import kaos.core.util.Msg;
import kaos.core.util.PolicyMsg;
import kaos.core.util.AttributeMsg;
import kaos.core.util.KAoSConstants;

import org.cougaar.planning.ldm.policy.Policy;
import org.cougaar.core.security.services.util.PolicyBootstrapperService;

import java.lang.reflect.*;
import java.util.Enumeration;
import java.util.List;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Vector;

import javax.agent.Locator;
import javax.naming.directory.InitialDirContext;

import safe.enforcer.*;
import safe.comm.*;
import safe.util.*;

import org.cougaar.core.security.policy.SecurityPolicy;
/**
 * NodeGuard implements a guard for a Cougaar node. A guard receives
 * policies from a policy manager and distributes the policies
 * to the appropriate enforcer(s) which have registered.
 * 
 * The guard should be instantiated and initialized as part of the
 * Node startup sequence, before any services, clusters, or any
 * other type of entity which might be controlled by an enforcer.
 * The Node must pass a reference to the MessageTransportService
 * to the guard when it becomes available. Otherwise, the guard
 * will never attempt to contact the policy manager.
 * 
 * Enforcers may be either node-level or agent-level, and should
 * obtain a reference to the guard for their VM by calling
 * the static method:
 * KAoS.enforcer.IGuard KAoS.enforcer.GuardRetriever.getGuard();
 * 
 * If the policy manager specified for this guard can't be immediately
 * contacted, the guard will continue polling the policy manager
 * at a settable interval, and register when contact is established.
 * 
 * If the policy manager is not available at the time an enforcer
 * registers, the enforcer will receive a default bootstrap policy,
 * if one has been defined for it in the Policy Bootstrapper passed
 * as an argument to the guard's constructor.
 * 
 */
public class NodeGuard implements Guard
{
    /**
     * Constructor
     * 
     * @param name          the name of the Node being guarded
     * @param id            the id of the Node being guarded
     * @param domainName    the name of the policy domain to register with
     * @param pb            the collection of bootstrap policies to use before the
     *                      Domain Manager has been contacted. Null is OK.
     */
    public NodeGuard (String name,
                      String nodeId,
                      String domainName,
		      PolicyBootstrapperService pb)
    {
        _name = name;
        _nodeId = nodeId;
        _myId = nodeId+"Guard";
        _domainName = domainName;
		_pb = pb;
        _myLocator = new CougaarLocator(_myId);
        _dmLocator = new CougaarLocator(_domainName);
        _vmId = VMIDGenerator.getInstance().vmID();
        
        _enforcersOfType = new Hashtable();            
        _agentDescriptions = new Vector();
        
        String debug = System.getProperty("SAFE.debug");
        if (debug != null && debug.equalsIgnoreCase("true")) {
            _debug = true;
        }        
    }
    
    /**
     * Initialize the Guard
     * 
     * @return boolean indicating whether initialization was successful
     */
    public boolean initialize ()
    {   
        try {
            _hostname = java.net.InetAddress.getLocalHost().getHostName();
            _hostAddress = java.net.InetAddress.getLocalHost().getHostAddress();
        }
        catch (Exception xcp) {
			xcp.printStackTrace();
			return false;
		}                            
        
        // set a reference to this guard in the GuardRetreiver
        GuardRetriever.setGuard(this);
		
		return true;
    }    
    
    /**
     * Sets the message transport service to use for communication with the
     * Domain Manager
     * 
     * @param mts     the Message Transport Service to use
     */
    public void setMessageTransport (org.cougaar.core.service.MessageTransportService mts)
    {
        CougaarMessageTransportService messageTransport = new CougaarMessageTransportService(mts);
        try {
            MessageReceiver receiver = messageTransport.newMessageReceiver();
            receiver.bindToLocalLocator(_myLocator);
            receiver.addMessageListener(new MyMessageListener());

            _sender = messageTransport.newMessageSender();
            _sender.bindToRemoteLocator(_dmLocator);
            
            // start trying to contact the Domain Manager
            DMReadyThread dmReadyThread = new DMReadyThread();
            dmReadyThread.start();
        }
        catch (Exception xcp) {
            xcp.printStackTrace();
        }                                 
    }
    
    /**
     * Implements interface KAoS.enforcer.IGuard
     * 
     * Registers a enforcer with the Guard
     * 
     * @param  enforcer        the enforcer that is being registered
     *                         Must implement SAFE.Enforcer.AgentEnforcer
     *                         or SAFE.Enforcer.NodeEnforcer
     * @param  enforcerType    a string identifying the type of the enforcer
     *                         only policies of the specified type will be sent to
     *                         the enforcer
     */
    public boolean registerEnforcer (Enforcer enforcer, String enforcerType)
    {
        if (enforcer instanceof AgentEnforcer) {
            AgentEnforcer agentEnforcer = (AgentEnforcer) enforcer;
            String agentId = agentEnforcer.getAgentId();
            if (agentId == null) {
                System.err.println("AgentEnforcer agentId == null!");
                return false;
            }
            String agentName = agentEnforcer.getAgentName();
            
            DefaultKAoSAgentDescription agentDescription = new DefaultKAoSAgentDescription();
            agentDescription.setEntityNameAsString(agentId);
            agentDescription.setAgentNickname(agentName);
            agentDescription.setAgentContainer(_nodeId);
            agentDescription.addDomainName(_domainName);
            agentDescription.addGuardID(_myId);
            agentDescription.setSupportsConversations(false);
            agentDescription.setExecutionEnv(_vmId);
            agentDescription.setHostAddress(_hostAddress);
            agentDescription.setHostName(_hostname);

            registerAgent (agentDescription);
            
            // get the hashtable of enforcers of 'enforcerType' type
            Hashtable enforcers = (Hashtable) _enforcersOfType.get(enforcerType);

            // create a new hashtable if it doesn't exist
            if (enforcers == null) {
                enforcers = new Hashtable();
                _enforcersOfType.put(enforcerType, enforcers);                
            }
            
            // add the enforcer to the hashtable
            enforcers.put(agentId, enforcer);
        }
        else if (enforcer instanceof NodeEnforcer) {
            if (_enforcersOfType.containsKey(enforcerType)) {
                System.err.println("NodeEnforcer of type "
                                   + enforcerType + " has already registered!");
                return false;
            }
            else {
                _enforcersOfType.put(enforcerType, enforcer);
                Vector args = new Vector();
                args.addElement(_myId);
                MethodCallRequestMsg registrationMsg = new MethodCallRequestMsg ("registerNodeEnforcer",
                                                                                 args);
                KAoSAcrNode node = new KAoSAcrNode(registrationMsg);
                Payload payload = new Payload(node);
                Envelope envelope = new Envelope();
                envelope.setSender(_myLocator);
                envelope.setReceiver(_dmLocator);
                TransportMessage message = new TransportMessage(envelope, payload);
                // if the message transport service has not been set, we don't need
                // to register the enforcer now because it will receive its policy
                // set when the guard registers.
                // TODO: In the future, we will need to change this
                // because guard registration should not automatically cause
                // policy distribution.
                if (_sender != null) {                    
                    try {
                        _sender.sendMessage(message);
                    }
                    catch (Exception xcp) {
		      System.out.println("Unable to send message:" + xcp);
                        xcp.printStackTrace();
                    }                    
                }
            }
        }
        
        // TODO: fix policy bootstrapper
        
        
        if (_pb != null) {
          PolicyMsg policies = null;
          try{
            // get the default policy for this type of enforcer
            policies = _pb.getBootPolicy(Class.forName(enforcerType));
          }catch(Exception e){
            e.printStackTrace();
          }
          
	  if (policies != null) {
	    Vector policyV = new Vector(1);
	    policyV.addElement(policies);

	    // send the policy to the enforcer
	    enforcer.receivePolicyUpdate(KAoSConstants.SET_POLICIES,
					 policyV);
	  }
        }
        		
        if (_debug) System.out.println("Guard: enforcer of type " + enforcerType + " registered successfully");
        
        return true;
    }
        
            
    /**
     * Private variables
     */   
    protected boolean _dmReady = false;
    private Hashtable _enforcersOfType;
    private String _name;    
    private String _myId;
    private String _nodeId;
    private String _hostname;
    private String _hostAddress;
    private String _domainName;
    private String _vmId;
    private MessageSender _sender;
    private Vector _agentDescriptions;
  private PolicyBootstrapperService _pb;
    private boolean _debug = false;
    private CougaarLocator _myLocator;
    private CougaarLocator _dmLocator;
    
    /**
     * Constants
     */
    private static final String NAI_POLICY_OBJECT = "POLICY_OBJECT";
    
    /**
     * Private classes
     */
    
    /**
     * DMReadyThread tries to establish contact with the policy manager by
     * checking to see if its message address is known to the NamingService
     * at a regular interval. After the policy manager is contacted,
     * the guard registers with the policy manager and flushes
     * the AgentRegistration message buffer.
     */
    private class DMReadyThread extends Thread
    {
        public void run()
        {
            if (_debug) System.out.println("Guard: attempting to reach Domain Manager...");                             
            DefaultKAoSEntityDescription guardInfo = new DefaultKAoSEntityDescription();
            guardInfo.addDomainName(_domainName);
            guardInfo.addLocator(_myLocator);
            guardInfo.setEntityNameAsString(_myId);
            guardInfo.setExecutionEnv(_vmId);
            guardInfo.setHostAddress(_hostAddress);
            guardInfo.setHostName(_hostname);
            
            // Hack for 3/1/02 deliverable
            guardInfo.set("ContainerID", _nodeId);
            
            Vector args = new Vector();
            args.addElement(guardInfo);
            MethodCallRequestMsg registrationMsg = new MethodCallRequestMsg("register",
                                                                            args);
            KAoSAcrNode node = new KAoSAcrNode(registrationMsg);
            Payload payload = new Payload(node);
            Envelope envelope = new Envelope();
            envelope.setSender(_myLocator);
            envelope.setReceiver(_dmLocator);
            TransportMessage message = new TransportMessage(envelope, payload);            
                        
            boolean delivered = false;            
            while (!delivered) {
                try {
                    try {
                        _sender.sendMessage(message);                    
                        delivered = true;
                    }
                    catch (javax.agent.service.transport.NotLocatableException nle) {
                        sleep (DM_LOOKUP_FREQUENCY);
                    }
                }
                catch (Exception xcp) {
                    xcp.printStackTrace();                    
                }
            }

            if (_debug) System.out.println("Guard: successfully registered with Domain Manager!");            
            _dmReady = true;
            
            // flush the agentRegistrations buffer
            registerAgent(null);            
        }

        private NodeGuard _guard;
        
        // The frequency (in milliseconds) with which the Domain Manager lookup
        // thread should attempt to contact the Domain Manager
        private static final long DM_LOOKUP_FREQUENCY = 5000;    
    }
    
    private class MyMessageListener implements MessageListener
    {
        /**
         * The callback method to be invoked.  When a message receiver
         * receives a message it calls back, to the MessageListener, via
         * this method.
         *
         * @param msg the incoming message.
         */
        public void receiveMessage (javax.agent.TransportMessage message)
        {
            KAoSAcrNode node = (KAoSAcrNode) message.getPayload().get(Payload.MESSAGE);
            Msg msg = node.getMsg();
            if (_debug) {
                System.out.println("Guard::MyMessageListener:receiveMessage:\n" + msg);
            }
            if (msg instanceof MethodCallRequestMsg) {
                satisfyRequest((MethodCallRequestMsg) msg,
                               message.getSender());
            }                
        }

        /**
         * A MessageListener needs a valid hash code for proper Set
         * operations.
         * @return a hash code value for this <tt>MessageListener</tt> object.
         */
        public int hashCode()
        {
            return _random.nextInt();
        }

        /**
         * A MessageListener needs a valid equals method for proper List
         * operations.
         *    
         * @param  o an Object to test against for equality.
         * @return true if the objects are equal; false otherwise.
         */
        public boolean equals (Object o)
        {
            if (o instanceof MyMessageListener) {
                MyMessageListener listener = (MyMessageListener) o;
                return (o.hashCode() == hashCode());
            }
            return false;
        }
        
        private java.util.Random _random = new java.util.Random();
    }
    
    /**
     * Private functions
     */
    private void satisfyRequest (MethodCallRequestMsg requestMsg, Locator requestor)
    {
        MethodCallResultMsg resultMsg = null;
        try {
            String methodName = requestMsg.getMethodName();
            Vector args = requestMsg.getArgs();
            if (args != null) {
                Class argClasses[] = new Class[args.size()];
                Object argObjects[] = new Object[args.size()];
                for (int i=0; i<args.size(); i++) {
                    argObjects[i] = args.elementAt(i);
                    argClasses[i] = args.elementAt(i).getClass();
                }
                
                // we have to check this the "hard way" because Class.getMethod(name, args[])
                // does not work if the args are subclasses of the parameter classes
                
                // find the method matching the method name requested
                Method methods[] = this.getClass().getDeclaredMethods();
                boolean foundMethod = false;
                for (int i=0; i<methods.length; i++) {                
                    if (methods[i].getName().equals(methodName)) {
                        // check to see if the parameter classes match the arguments                    
                        Class parameters[] = methods[i].getParameterTypes();
                        boolean classesMatch = true;
                        for (int j=0; j<parameters.length; j++) {
                            if (!parameters[j].isAssignableFrom(argClasses[j])) {
                                classesMatch = false;
                                break;
                            }
                        }
                        // if we found the right method, execute it
                        if (classesMatch) {
                            foundMethod = true;
                            Object result = methods[i].invoke(this, argObjects);
                            resultMsg = new MethodCallResultMsg(requestMsg.getSequenceId(),
                                                                result);
                            break;
                        }
                    }
                }
                // if we didn't find the method, throw an exception
                if (!foundMethod) {
                    throw new NoSuchMethodException(methodName);
                }
            }
            // args == null, invoke method with no args
            else {
                Object result = this.getClass().getDeclaredMethod(methodName, null).invoke(this, null);
                resultMsg = new MethodCallResultMsg(requestMsg.getSequenceId(),
                                                    result);                
            }
        }
        catch (Exception xcp) {
            xcp.printStackTrace();
            resultMsg = new MethodCallResultMsg(requestMsg.getSequenceId(),
                                                xcp);
        }
        
        // send the result message
        try {
            // wrap resultMsg in a TransportMessage
            ri.message.Envelope envelope = new ri.message.Envelope();
            envelope.setSender(_myLocator);
            envelope.setReceiver(requestor);
            ri.message.Payload payload = new ri.message.Payload(new KAoSAcrNode(resultMsg));
            ri.message.TransportMessage outgoingMessage = new ri.message.TransportMessage(envelope,
                                                                                          payload);        
            _sender.sendMessage(outgoingMessage);
        }
        catch (Exception xcp) {
            xcp.printStackTrace();
        }
    }
	
    /**
     * Sends a message to the Domain Manager to register an agent
     * If the Domain Manager is not ready yet, puts the message in a queue.
     *
     * @param agentDescription    description of the agent
     *                            (null to only flush the buffer)
     */
    protected synchronized void registerAgent (DefaultKAoSAgentDescription agentDescription)
    {
        if (_dmReady) {
            // flush the agentDescriptions buffer
            while (_agentDescriptions.size() > 0) {
                if (_debug) System.out.println("Guard: Registering governable agent");
                DefaultKAoSAgentDescription ad = (DefaultKAoSAgentDescription) _agentDescriptions.elementAt(0);
                
                Vector args = new Vector();
                args.addElement(ad);
                MethodCallRequestMsg registrationMsg = new MethodCallRequestMsg ("register",
                                                                                 args);
                KAoSAcrNode node = new KAoSAcrNode(registrationMsg);
                Payload payload = new Payload(node);
                Envelope envelope = new Envelope();
                envelope.setSender(_myLocator);
                envelope.setReceiver(_dmLocator);
                TransportMessage message = new TransportMessage(envelope, payload);
                try {
                    _sender.sendMessage(message);
                }
                catch (Exception xcp) {
                    xcp.printStackTrace();
                }                    
                _agentDescriptions.removeElementAt(0);
            }
            
            // could be null if this function was called just to flush the buffer
            if (agentDescription != null) {
                // send the AgentDescription
                if (_debug) System.out.println("Guard: Registering governable agent");
                
                Vector args = new Vector();
                args.addElement(agentDescription);
                MethodCallRequestMsg registrationMsg = new MethodCallRequestMsg ("register",
                                                                                 args);
                KAoSAcrNode node = new KAoSAcrNode(registrationMsg);
                Payload payload = new Payload(node);
                Envelope envelope = new Envelope();
                envelope.setSender(_myLocator);
                envelope.setReceiver(_dmLocator);
                TransportMessage message = new TransportMessage(envelope, payload);
                try {
                    _sender.sendMessage(message);
                }
                catch (Exception xcp) {
                    xcp.printStackTrace();
                }                    
            }
        }
        else {        
            _agentDescriptions.addElement(agentDescription);
        }
    }
    
    /**
     * 
     * Distributes a policy message to the appropriate enforcer(s)
     * 
     * @param aMsg      the policy message
     */
    private void updatePolicies (String updateType,
                                 List policies)
    {		
        if (_debug) {
            System.out.println("Guard::updatePolicies");
            System.out.println("updateType = " + updateType);
            System.out.println(policies);           
        }
        
        Iterator policiesIt = policies.iterator();
        HashMap policiesByType = new HashMap();
        while (policiesIt.hasNext()) {
            PolicyMsg policyMsg = (PolicyMsg) policiesIt.next();
            String enforcerType = policyMsg.getPolicyType();
            if (!policiesByType.containsKey(enforcerType)) {
                policiesByType.put(enforcerType, new Vector());
            }
            Vector enforcerPolicies = (Vector) policiesByType.get(enforcerType);
            enforcerPolicies.addElement(policyMsg);
        }
        
        Iterator enforcerTypes = policiesByType.keySet().iterator();
        while (enforcerTypes.hasNext()) {
            String enforcerType = (String) enforcerTypes.next();
            Vector enforcerPolicies = (Vector) policiesByType.get(enforcerType);
            Object enforcer = _enforcersOfType.get(enforcerType);                                    
            if (enforcer != null) {
                if (enforcer instanceof Enforcer) {
                    if (_debug) System.out.println("Sending policy update to node-level" + 
                                                   " enforcer of type " + enforcerType);
                    ((Enforcer) enforcer).receivePolicyUpdate(updateType,
                                                              enforcerPolicies);
                }
                else if (enforcer instanceof Hashtable) {
                    if (_debug) System.out.println("Sending policy update to agent-level" +
                                                   " enforcers of type " + enforcerType);
                    Hashtable h = (Hashtable) enforcer;
                    Enumeration enforcers = h.elements();
                    while (enforcers.hasMoreElements()) {
                        ((Enforcer) enforcers.nextElement()).receivePolicyUpdate(updateType,
                                                                                 enforcerPolicies);
                    }
                }              
            }
            else {
                System.err.println("No enforcers of type " + enforcerType +
                                   " are registered!");
            }              
        }
    }
}

package safe.policyManager;

import javax.agent.service.transport.MessageListener;
import javax.agent.service.transport.MessageReceiver;
import javax.agent.service.transport.MessageSender;
import javax.agent.service.directory.AgentDescription;
import javax.agent.Locator;

import kaos.core.util.KAoSConstants;
import kaos.core.util.MethodCallRequestMsg;
import kaos.core.util.MethodCallResultMsg;
import kaos.core.util.Msg;
import kaos.core.util.PolicyMsg;
import kaos.core.util.UniqueIdentifier;
import kaos.core.service.directory.KAoSDirectoryService;
import kaos.core.message.KAoSAcrNode;
import kaos.core.service.directory.DefaultKAoSAgentDescription;
import kaos.core.service.directory.DefaultKAoSEntityDescription;
import kaos.core.service.directory.KAoSEntityDescription;
import kaos.core.service.directory.KAoSAgentDescription;

import ri.message.Payload;
import ri.message.Envelope;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.lang.reflect.Method;


public class DomainManager
{    
    public DomainManager (String domainName,
                          MessageReceiver receiver,
                          MessageSender sender)
    {
        _domainName = domainName;
        _receiver = receiver;
        try {
            _receiver.addMessageListener(new MyMessageListener());
        }
        catch (Exception xcp) {
            xcp.printStackTrace();
        }
        _sender = sender;
        _ds = new KAoSDirectoryService (_domainName);
    }
    
    public Msg getPolicy (String policyId)
    {
        return _ds.getPolicy(policyId);
    }
    
    /**
     * Rehydrate policies
     * 
     * Adds the policies to the directory service, but does not distribute
     * them. Should only be used when restarting the domain manager in a
     * running domain.
     */
    public void rehydratePolicies (List policies)
    {
        _ds.addPolicies((Vector) policies);
    }
    
    public void addPolicies (List policies)
    {
        System.out.println("DomainManager::addPolicies:\n" + policies);
        _ds.addPolicies((Vector) policies);
        distributeUpdatedPolicies(KAoSConstants.ADD_POLICIES, policies);
    }
    
    public void changePolicies (List policies)
    {
        System.out.println("DomainManager::changePolicies:\n" + policies);
        _ds.changePolicies((Vector) policies);
        distributeUpdatedPolicies(KAoSConstants.CHANGE_POLICIES, policies);
    }

    public void removePolicies (List policies)
    {
        System.out.println("DomainManager::removePolicies:\n" + policies);
        _ds.removePolicies((Vector) policies);
        distributeUpdatedPolicies(KAoSConstants.REMOVE_POLICIES, policies);
    }

    public void register (AgentDescription agentDescrip)
    {
        System.out.println("DomainManager::register");
        KAoSEntityDescription entityDescrip = (KAoSEntityDescription) agentDescrip;
        String entityId = entityDescrip.getEntityNameAsString();
        
        System.out.println("entity id = " + entityId);
        // if the entity has not registered yet, register it
        // TODO: authentication to make sure the entity is the same as already registered        
        if (!_ds.isEntityInDomain(entityId)) {
            System.out.println("entity is not in domain, registering");
            try {                
                _ds.register(agentDescrip);
                
            }
            catch (Exception xcp) {
                xcp.printStackTrace();
            }
        }
        else {
            System.out.println("entity IS in domain, modifying");
            try {
                _ds.modify(agentDescrip);
            }
            catch (Exception xcp) {
                xcp.printStackTrace();
            }
        }
        
        // get the guard id for this entity
        String guardId = null;        
        if (entityDescrip instanceof KAoSAgentDescription) {
            // entity is an agent, get its guard id from its description
            List guardIds = ((KAoSAgentDescription) entityDescrip).getGuardIDs();
            if (guardIds != null) {
                guardId = (String) guardIds.get(0);
            }
        }
        else {
            // entity is a guard, so guard id = entity id
            guardId = entityId;
        }
        
        if (guardId != null) {
            distributeUpdatedPolicies(KAoSConstants.SET_POLICIES,
                                      _ds.getPolicies(),
                                      guardId);
        }
    }
    
    public void registerNodeEnforcer (String guardId)
    {
        distributeUpdatedPolicies(KAoSConstants.SET_POLICIES,
                                  _ds.getPolicies(),
                                  guardId);        
    }
    
    public Map getDomainStructure()
    {
        System.out.println("DomainManager::getDomainStructure");
        return _ds.getDomainStructure();
    }
    
    public Map getPoliciesByEntity()
    {
        System.out.println("DomainManager::getPoliciesByEntity");
        return _ds.getPoliciesByEntities();
    }
    
    /**
     * Distribute updated "in-force" policies to the appropriate guards
     * in the domain
     */    
    private void distributeUpdatedPolicies (String updateType,
                                            List policies)
    {
        distributeUpdatedPolicies(updateType,
                                  policies,
                                  null);
    }
    
    /**
     * Distribute updated "in-force" policies to a particular guard
     */    
    private void distributeUpdatedPolicies (String updateType,
                                            List policies,
                                            String guardId)
    {
        // create table of policies
        // key = subjectId, value = Vector of PolicyMsg
        HashMap policyTable = new HashMap(policies.size());
        Iterator it = policies.iterator();
        while (it.hasNext()) {
            PolicyMsg policyMsg = (PolicyMsg) it.next();
            // only distribute "in-force" policies
            if (policyMsg.isInForce()) {
                String subjectId = policyMsg.getSubjectId();
                if (!policyTable.containsKey(subjectId)) {
                    policyTable.put(subjectId, new Vector());
                }
                Vector policyV = (Vector) policyTable.get(subjectId);
                policyV.addElement(policyMsg);
            }
        }
        
        Enumeration guardIds = null;
        if (guardId != null) {
            Vector guardIdsV = new Vector(1);
            guardIdsV.addElement(guardId);
            guardIds = guardIdsV.elements();
        }
        else {
            guardIds = _ds.getGuards();
        }
            
        // get the guards in this domain
        while (guardIds.hasMoreElements()) {
            guardId = (String) guardIds.nextElement();
            Map guardInfo = _ds.getGuardInfo(guardId);
            KAoSEntityDescription guardDescrip = (KAoSEntityDescription) guardInfo.get(_ds.MY_DESCRIPTION);
            Locator guardLocator = guardDescrip.getLocators()[0]; //TODO: support multiple locators?
            String execEnvId = guardDescrip.getExecutionEnv();
            String hostId = guardDescrip.getHostAddress();            
            Vector policyV = new Vector();
            
            // add policies for this domain
            Vector domainPolicies = (Vector) policyTable.get(_domainName);
            if (domainPolicies != null) {
                for (int i=0; i<domainPolicies.size(); i++) {
                    policyV.addElement(domainPolicies.elementAt(i));
                }
            }
            
            // add policies for this host
            Vector hostPolicies = (Vector) policyTable.get(hostId);
            if (hostPolicies != null) {
                for (int i=0; i<hostPolicies.size(); i++) {
                    policyV.addElement(hostPolicies.elementAt(i));
                }
            }
            
            // add policies for this execEnv
            Vector execEnvPolicies = (Vector) policyTable.get(execEnvId);
            if (execEnvPolicies != null) {
                for (int i=0; i<execEnvPolicies.size(); i++) {
                    policyV.addElement(execEnvPolicies.elementAt(i));
                }
            }
            
            // get the guarded entities for this guard
            Map guardedEntities = (Map) guardInfo.get(_ds.GUARDED_ENTITIES);
            // get the guarded containers
            Iterator containerIds = ((Map) guardedEntities.get(_ds.CONTAINERS)).keySet().iterator();
            while (containerIds.hasNext()) {
                // add the policies for this container
                Vector containerPolicies = (Vector) policyTable.get((String) containerIds.next());
                if (containerPolicies != null) {
                    for (int i=0; i<containerPolicies.size(); i++) {
                        policyV.addElement(containerPolicies.elementAt(i));
                    }
                }
            }
            // get the guarded agents
            Map guardedAgents = (Map) guardedEntities.get(_ds.AGENTS);
            if (guardedAgents != null) {
                Iterator agentIds = guardedAgents.keySet().iterator();
                while (agentIds.hasNext()) {
                    // add the policies for this agent
                    Vector agentPolicies = (Vector) policyTable.get((String) agentIds.next());                    
                    if (agentPolicies != null) {
                        for (int i=0; i<agentPolicies.size(); i++) {
                            policyV.addElement(agentPolicies.elementAt(i));
                        }
                    }
                }
            }
            
            // send the policies
            if (updateType.equals(KAoSConstants.SET_POLICIES) ||
                 !policyV.isEmpty()) {
                sendPolicyUpdate (updateType, guardLocator, policyV);
            }
        }
    }
    
    /**
     * Sends a policy update to a guard
     * 
     * @param Locator       locator for the guard
     */
    private void sendPolicyUpdate (String updateType,
                                   Locator locator,
                                   List policies)
    {
        Vector args = new Vector(2);
        args.addElement(updateType);
        args.addElement(policies);        MethodCallRequestMsg requestMsg = new MethodCallRequestMsg(UniqueIdentifier.GenerateUID(),
                                                                   "updatePolicies",                                                                   args);        
        // send the policy update msg
        try {
            // wrap requestMsg in a TransportMessage
            ri.message.Envelope envelope = new ri.message.Envelope();
            envelope.setSender(_receiver.getLocalLocator());
            envelope.setReceiver(locator);
            ri.message.Payload payload = new ri.message.Payload(new KAoSAcrNode(requestMsg));
            ri.message.TransportMessage outgoingMessage = new ri.message.TransportMessage(envelope,
                                                                                          payload);        
            try {
                _sender.sendMessage(outgoingMessage);
            }
            catch (javax.agent.service.transport.NotLocatableException nle) {
                System.err.println("DomainManager::sendPolicyMsg: Error: message transport service unable to locate address " + locator.getAddress());
            }
        }
        catch (Exception xcp) {
            xcp.printStackTrace();
        }        
    }
    
    private void satisfyRequest (MethodCallRequestMsg requestMsg, Locator requestor)
    {
        MethodCallResultMsg resultMsg = null;
        try {            String methodName = requestMsg.getMethodName();
            Vector args = requestMsg.getArgs();            if (args != null) {
                Class argClasses[] = new Class[args.size()];
                Object argObjects[] = new Object[args.size()];                for (int i=0; i<args.size(); i++) {
                    argObjects[i] = args.elementAt(i);                    argClasses[i] = args.elementAt(i).getClass();
                }
                                // we have to check this the "hard way" because Class.getMethod(name, args[])                // does not work if the args are subclasses of the parameter classes                
                // find the method matching the method name requested                Method methods[] = this.getClass().getMethods();                boolean foundMethod = false;
                for (int i=0; i<methods.length; i++) {                                    if (methods[i].getName().equals(methodName)) {                        // check to see if the parameter classes match the arguments                    
                        Class parameters[] = methods[i].getParameterTypes();                        boolean classesMatch = true;
                        for (int j=0; j<parameters.length; j++) {
                            if (!parameters[j].isAssignableFrom(argClasses[j])) {                                classesMatch = false;
                                break;                            }                        }
                        // if we found the right method, execute it                        if (classesMatch) {                            foundMethod = true;                            Object result = methods[i].invoke(this, argObjects);                            resultMsg = new MethodCallResultMsg(requestMsg.getSequenceId(),
                                                                result);                            break;                        }                    }                }
                // if we didn't find the method, throw an exception                if (!foundMethod) {                    throw new NoSuchMethodException(methodName);                }            }
            // args == null, invoke method with no args            else {
                Object result = this.getClass().getMethod(methodName, null).invoke(this, null);
                resultMsg = new MethodCallResultMsg(requestMsg.getSequenceId(),
                                                    result);                            }
        }        catch (Exception xcp) {            xcp.printStackTrace();
            resultMsg = new MethodCallResultMsg(requestMsg.getSequenceId(),
                                                xcp);
        }
                // send the result message
        try {
            // wrap resultMsg in a TransportMessage
            ri.message.Envelope envelope = new ri.message.Envelope();
            envelope.setSender(_receiver.getLocalLocator());
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
    
    private MessageReceiver _receiver;
    private MessageSender _sender;
    private KAoSDirectoryService _ds;
    private String _domainName;

    private class MyMessageListener implements MessageListener
    {
        /**
         * The callback method to be invoked.  When a message receiver
         * receives a message it calls back, to the MessageListener, via
         * this method.
         *
         * @param msg the incoming message.
         */
        public void receiveMessage (javax.agent.TransportMessage transportMessage)        {
            Locator sourceLocator = transportMessage.getSender();            KAoSAcrNode node = (KAoSAcrNode) transportMessage.getPayload().get(Payload.MESSAGE);
            Msg msg = node.getMsg();            System.out.println("DomainManager::MyMessageListener:receiveMessage:\n" + msg);
            if (msg instanceof MethodCallRequestMsg) {                satisfyRequest((MethodCallRequestMsg) msg, sourceLocator);
            }
            else {
                System.out.println("DomainManager::received unsupported message type: " + msg.getClass().toString());
            }        }
        
        /**
         * A MessageListener needs a valid hash code for proper Set
         * operations.
         * @return a hash code value for this <tt>MessageListener</tt> object.
         */
        public int hashCode()        {
            return _random.nextInt();        }

        /**
         * A MessageListener needs a valid equals method for proper List
         * operations.
         *    
         * @param  o an Object to test against for equality.
         * @return true if the objects are equal; false otherwise.
         */
        public boolean equals (Object o)        {            if (o instanceof MyMessageListener) {                MyMessageListener listener = (MyMessageListener) o;
                return (o.hashCode() == hashCode());
            }
            return false;        }
        
        private java.util.Random _random = new java.util.Random();    }
    
}

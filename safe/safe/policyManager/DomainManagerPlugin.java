/**
 * Last Modified by: $Author: srosset $
 * On: $Date: 2002-05-17 23:18:09 $
 */package safe.policyManager;

import org.cougaar.core.plugin.SimplePlugin;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.service.MessageTransportService;
import org.cougaar.core.mts.MessageTransportClient;
import org.cougaar.core.mts.Message;
import org.cougaar.core.mts.MessageAddress;
//import org.cougaar.domain.planning.ldm.plan.*;
import org.cougaar.util.UnaryPredicate;

//import KAoS.GUI.DomainManagerGUI;
//import KAoS.Ext.IAgentStateListener;
//import KAoS.KPAT.message.PolicyMsg;
//import KAoS.Util.Logger;
import kaos.core.util.KAoSConstants;
import kaos.core.util.Msg;
import kaos.core.util.PolicyMsg;
import kaos.core.service.directory.KAoSEntityDescription;
import kaos.core.policyManagement.PolicyManager;
import kaos.core.service.directory.KAoSDirectoryService;
import kaos.core.service.transport.CougaarMessageTransportService;
import kaos.core.service.util.CougaarLocator;
//import KAoS.Policy.PolicyConstants;

import safe.comm.*;
import safe.util.ConditionalPolicyMsg;
import safe.util.ProposedPolicyUpdate;
import safe.util.UnexpandedPolicyUpdate;
import safe.util.UnexpandedConditionalPolicyMsg;

//import safe.util.ProposedPolicyMsg;

import javax.agent.service.transport.MessageReceiver;
import javax.agent.service.transport.MessageSender;
import javax.agent.service.directory.AgentDescription;

import java.util.Enumeration;
import java.util.Iterator;
import java.util.Collection;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Vector;
import java.util.HashMap;
import java.util.StringTokenizer;
import java.util.List;

/**
 * The DomainManagerPlugin acts as a Message Transport Client
 * 
 * It receives registration messages from guards
 * 
 * It subscribes to ProposedPolicyMsgs, which it processes and distributes to guards
 * 
 * It publishes PolicyMsgs, GuardRegistrations, and AgentRegistrations
 */
public class DomainManagerPlugin extends SimplePlugin implements MessageTransportClient
{
    public void setupSubscriptions()
    {
        // should we print debugging info?
        String debug = System.getProperty("SAFE.debug");
        if (debug != null && debug.equalsIgnoreCase("true")) {
            _debug = true;
        }
        
        // get handle to message transport service        
        try {
            MessageTransportService mts = (MessageTransportService) this.getBindingSite().getServiceBroker().getService(this,
                                                                                                                        MessageTransportService.class,
                                                                                                                        null);
            
            // get the name of the domain we are managing
            String domainName = System.getProperty("org.cougaar.safe.domainName");
            if (domainName == null) {
                throw new NullPointerException("System property org.cougaar.safe.domainName is not set");
            }                        

            // create MessageSender and MessageReceiver for DM
            // create local locator and bind MessageReceiver to it
            CougaarMessageTransportService messageTransport = new CougaarMessageTransportService(mts);
            MessageSender sender = messageTransport.newMessageSender();
            MessageReceiver receiver = messageTransport.newMessageReceiver();            
            CougaarLocator myLocator = new CougaarLocator(domainName);
            receiver.bindToLocalLocator(myLocator);
            
            // create Domain Manager
            _dm = new MyDomainManager(domainName,
                                      receiver,
                                      sender);
            
        }
        catch (Exception xcp) {
            xcp.printStackTrace();
        }
               
        // BEGIN rehydrate        
        
        // rehydrate: get entity descriptions from the blackboard and register them
        // with the domain manager
        Iterator entityDescriptions = query(_entityDescriptionPredicate).iterator();
        Vector nonGuardDescrips = new Vector();
        while (entityDescriptions.hasNext()) {            
            KAoSEntityDescription entityDescrip = (KAoSEntityDescription) entityDescriptions.next();
            // register all the guards first
            if (entityDescrip.getEntityType().equals(KAoSConstants.GUARD)) {                
                _dm.register(entityDescrip, true);
            }
            else {
                nonGuardDescrips.addElement(entityDescrip);
            }
        }
        // then register the other entities
        for (int i=0; i<nonGuardDescrips.size(); i++) {
            _dm.register((KAoSEntityDescription) nonGuardDescrips.elementAt(i), true);
        }
        
        // rehydrate: get policies from the blackboard and give
        // them to the domain manager
        Iterator policyMsgs = query(_policyMsgPredicate).iterator();
        Vector policyMsgsV = new Vector();
        while (policyMsgs.hasNext()) {
            policyMsgsV.addElement(policyMsgs.next());
        }
        _dm.rehydratePolicies(policyMsgsV);
        
        // END rehydrate
        
        _proposedPolicyUpdate = (IncrementalSubscription) subscribe(_proposedPolicyUpdatePredicate);        
    }
    
    
    public void execute()
    {
        if (_debug) System.out.println("DMPlugIn::execute()");
        Iterator it = _proposedPolicyUpdate.getAddedCollection().iterator();
        while (it.hasNext()) {
            ProposedPolicyUpdate ppu = (ProposedPolicyUpdate) it.next();
            if (_debug) System.out.println("about to call updatePolicies");
            _dm.updatePolicies(ppu.getUpdateType(),
                               ppu.getPolicies(),
                               true);
            publishRemove(ppu);
        }            
    }
    
    // implement MessageTransportClient
    public void receiveMessage(Message m) {}
    public MessageAddress getMessageAddress() {return null;}
        
    /**
     * Strips the POLICY_INFORCE, POLICY_FIXED_SET, and POLICY_SINGLE_VALUED symbols
     * from a message
     */
    /*
    private void stripBooleans (Msg msg) {
        try {
            msg.removeSymbol(PolicyMsg.POLICY_INFORCE);
            msg.removeSymbol(PolicyMsg.POLICY_FIXED_SET);
            msg.removeSymbol(PolicyMsg.POLICY_SINGLE_VALUED);
        }
        catch (Exception xcp) {
            xcp.printStackTrace();
        }
    }
    */
    /**
     * Removes attributes which are unselected from a message
     */
    /*
    private void stripUnselectedAttribs (Msg msg) {
        try {
            Vector attribs = msg.getNamedVector(PolicyConstants.HLP_POLICY_ATTRIBUTES_SYMBOL);
            Vector selectedAttribs = new Vector();
            if (attribs != null) {
                for (int i=0; i<attribs.size(); i++) {
                    Msg attrib = (Msg) attribs.elementAt(i);
                    if (PolicyMsg.getAttributeIsSelected(attrib)) {
                        selectedAttribs.addElement(attrib);
                    }
                }
                msg.addSymbol(PolicyConstants.HLP_POLICY_ATTRIBUTES_SYMBOL,
                              selectedAttribs);
            }
        }
        catch (Exception xcp) {
            xcp.printStackTrace();
        }
    }                                                                                    
    */
    
                
    // Unary Predicate for ConditionalPolicyMsg    
    private UnaryPredicate conditionalPolicyMsgPredicate = new UnaryPredicate() {
        public boolean execute (Object o)
        {
            return (o instanceof ConditionalPolicyMsg);
        }
        };
    

    // Unary Predicate for ProposedPolicyUpdate
    private UnaryPredicate _proposedPolicyUpdatePredicate = new UnaryPredicate() {
        public boolean execute (Object o)
        {
            return (o instanceof ProposedPolicyUpdate);
        }
        };

    // Unary Predicate for PolicyMsg
    private UnaryPredicate _policyMsgPredicate = new UnaryPredicate() {
        public boolean execute (Object o)
        {
            return (o instanceof PolicyMsg);
        }
        };
    
    // Unary Predicate for KAoSEntityDescription
    private UnaryPredicate _entityDescriptionPredicate = new UnaryPredicate() {
        public boolean execute (Object o)
        {
            return (o instanceof KAoSEntityDescription);
        }
        };
        
    
    private class MyDomainManager extends DomainManager
    {               
        public MyDomainManager (String domainName,
                                MessageReceiver receiver,
                                MessageSender sender)
        {
            super(domainName, receiver, sender);
        }
        
        // overrides superclass
        public void register (AgentDescription agentDescrip)
        {
            register (agentDescrip, false);
        }
        
        public void register (AgentDescription agentDescrip, boolean rehydrate)
        {
            KAoSEntityDescription entityDescrip = (KAoSEntityDescription) agentDescrip;
            super.register(entityDescrip);            
            if (!rehydrate) {
                openTransaction();
                Iterator entities = query(_entityDescriptionPredicate).iterator();
                while (entities.hasNext()) {
                    KAoSEntityDescription descrip = (KAoSEntityDescription) entities.next();
                    if (descrip.getEntityNameAsString().equals(entityDescrip.getEntityNameAsString())) {
                        publishRemove(descrip);
                    }
                }
                    
                publishAdd(entityDescrip);
                closeTransaction();
            }
            
        }
        
        /*
        public void unregister (KAoSEntityDescription entityDescrip) {
            super.unregister (entityDescrip);
            publishRemove (entityDescrip);
        }
        */
        
        // overrides superclass
        public void addPolicies (List policies)
        {
            expandPolicyUpdate (KAoSConstants.ADD_POLICIES,
                                policies);
        }
                    
        // overrides superclass
        public void changePolicies (List policies)
        {
            expandPolicyUpdate (KAoSConstants.CHANGE_POLICIES,
                                policies);
        }

        // overrides superclass
        public void removePolicies (List policies)
        {
            expandPolicyUpdate (KAoSConstants.REMOVE_POLICIES,
                                policies);
        }
                
        public Vector getConditionalPolicies()
        {
            Vector conditionalPolicies = new Vector();
            openTransaction();
            Iterator it = query(conditionalPolicyMsgPredicate).iterator();
            closeTransaction();
            while (it.hasNext()) {
                conditionalPolicies.addElement(it.next());
            }
            return conditionalPolicies;
        }
        
        public void setConditionalPolicies (Vector conditionalPolicies)
        {
            // TODO: make this more efficient
            
            // remove existing ConditionalPolicyMsgs
            openTransaction();
            Iterator it = query(conditionalPolicyMsgPredicate).iterator();
            while (it.hasNext()) {
                publishRemove(it.next());
            }
            
            // add new ConditionalPolicyMsgs
            for (int i=0; i<conditionalPolicies.size(); i++) {
                ConditionalPolicyMsg condPol = (ConditionalPolicyMsg) conditionalPolicies.elementAt(i);
                UnexpandedConditionalPolicyMsg ucpm = new UnexpandedConditionalPolicyMsg(condPol);
                publishAdd(ucpm);
            }
            closeTransaction();
        }
        
        protected void updatePolicies (String updateType,
                                       List policies)
        {
            updatePolicies (updateType,
                            policies,
                            false);
        }
        
        protected void updatePolicies (String updateType,
                                       List policies,
                                       boolean isTransactionOpen)
        {
            if (updateType.equals(KAoSConstants.ADD_POLICIES)) {
                super.addPolicies(policies);
                Iterator it = policies.iterator();                
                if (!isTransactionOpen) openTransaction();
                while (it.hasNext()) {
                    publishAdd(it.next());
                }
                if (!isTransactionOpen) closeTransaction();
            }
            else if (updateType.equals(KAoSConstants.CHANGE_POLICIES)) {
                Vector oldPolicies = new Vector(policies.size());
                Iterator it = policies.iterator();
                while (it.hasNext()) {
                    PolicyMsg policyMsg = (PolicyMsg) it.next();
                    oldPolicies.addElement(_dm.getPolicy(policyMsg.getId()));
                }
                
                super.changePolicies(policies);
                
                // publishChange doesn't work for cloned PolicyMsg, so
                // remove old policies and add new policies
                if (!isTransactionOpen) openTransaction();
                for (int i=0; i<oldPolicies.size(); i++) {
                    publishRemove(oldPolicies.elementAt(i));
                }
                it = policies.iterator();
                while (it.hasNext()) {
                    publishAdd(it.next());
                }
                if (!isTransactionOpen) closeTransaction();
            }
            else if (updateType.equals(KAoSConstants.REMOVE_POLICIES)) {
                // publishRemove doesn't work for cloned PolicyMsg,
                // so get the old policies and remove them
                Vector oldPolicies = new Vector(policies.size());
                Iterator it = policies.iterator();
                while (it.hasNext()) {
                    PolicyMsg policyMsg = (PolicyMsg) it.next();
                    oldPolicies.addElement(_dm.getPolicy(policyMsg.getId()));
                }
                
                super.removePolicies(policies);
                if (!isTransactionOpen) openTransaction();
                for (int i=0; i<oldPolicies.size(); i++) {
                    publishRemove(oldPolicies.elementAt(i));
                }
                if (!isTransactionOpen) closeTransaction();
            }
            else {
                throw new UnsupportedOperationException(updateType);
            }
        }
        
        private void expandPolicyUpdate (String updateType,
                                         List policies)
        {     
            UnexpandedPolicyUpdate upu = new UnexpandedPolicyUpdate(updateType,
                                                                    policies);
            openTransaction();
            publishAdd(upu);
            closeTransaction();            
        }
            
    }
        
    private void printDebugString (String s, int level) {
        if (_debug) System.out.println(s);
    }
    
    private IncrementalSubscription _proposedPolicyUpdate;
    //private DomainManagerGUI _dmGUI;
    private String _domainName = "Test Domain";
    private Hashtable _agentIdToGuardId;
    private Hashtable _guardIdToGuardAddress;
    private MessageTransportService _mts;
    private MessageAddress _thisAddress;
    private Vector _agentList;
    private MyDomainManager _dm;
    private boolean _debug = false;
    private KAoSDirectoryService _ds;
}

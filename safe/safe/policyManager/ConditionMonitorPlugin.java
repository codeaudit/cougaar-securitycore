package safe.policyManager;

import org.cougaar.core.plugin.SimplePlugin;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.util.UnaryPredicate;

import java.io.Serializable;
import java.lang.reflect.*;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Vector;
    
import safe.util.*;
import kaos.core.util.*;

/**
 * The ConditionMonitorPlugin adds conditional policies to the existing
 * policy set when their condition(s) become true, and removes them
 * when their condition(s) become false.
 * 
 * It subscribes to ConditionalPolicyMsgs, and to objects of the type
 * specified in those messages that will satisfy the condition(s).
 * 
 * It publishes ProposedPolicyUpdate when conditions change.
 * 
 */
    
public class ConditionMonitorPlugin extends SimplePlugin {
    
    //Variables
    
    protected IncrementalSubscription messages_;
    private boolean _debug = false;
    private Vector _conditionSubscriptions;

    // UnaryPredicate for ConditionalPolicyMsg
    private UnaryPredicate conditionalPolicyMsgPredicate_ = new UnaryPredicate() {
        public boolean execute(Object o) {
            return (o instanceof ConditionalPolicyMsg);
        }
        };
    
    // UnaryPredicate for PolicyMsg
    private UnaryPredicate policyMsgPredicate_ = new UnaryPredicate() {
        public boolean execute(Object o) {
            return (o instanceof PolicyMsg);
        }
        };
    
    // UnaryPredicate for objects of the type specified in a trigger
    // condition
    private class TriggerConditionPredicate implements UnaryPredicate
    {
        public TriggerConditionPredicate (TriggerCondition tc) throws ClassNotFoundException {      
            _triggerClass = Class.forName(tc.getClassName());
        }
        
        public boolean execute (Object o) {
            return (_triggerClass.equals(o.getClass()));
        }
        
        private Class _triggerClass;
    }

    // Unary predicate for objects of the type specified in a trigger
    // condition if they satisfy the condition
    private class TriggerConditionTruePredicate implements UnaryPredicate
    {
        private TriggerCondition tc_;
        
        public TriggerConditionTruePredicate (TriggerCondition tc){
            tc_ = tc;
        }
        
        public boolean execute (Object o){
            Class triggerClass = null;
            try{
                triggerClass = Class.forName(tc_.getClassName());
            }
            catch(java.lang.ClassNotFoundException cnfe){
                cnfe.printStackTrace();
                return false;
            }
            
            Class oClass = o.getClass();
            if (triggerClass == oClass) {
                Field fld;
                try{
                    fld = triggerClass.getDeclaredField(tc_.getFieldName());
                }
                catch(NoSuchFieldException e1){
                    e1.printStackTrace();
                    return false;
                }
                catch(SecurityException e2){
                    e2.printStackTrace();
                    return false;
                }
                
                Object obj;
                try{
                    obj = fld.get(o);
                }
                catch(IllegalArgumentException e3){
                    e3.printStackTrace();
                    return false;
                }
                catch(IllegalAccessException e4){
                    e4.printStackTrace();
                    return false;
                }
                
                Serializable val;
                try{
                    val = (Serializable) obj;
                }
                catch(ClassCastException e5){
                    e5.printStackTrace();
                    return false;
                }
                
                return (val.equals(tc_.getValue()));
            }
            return false;
        }
    }

    /**
     * Takes an Enumeration of ConditionalPolicyMsgs and subscribes
     * to the objects of the type specified in each Trigger Condition
     */
    private void setupConditionSubscriptions(Enumeration condPolicies)
    {
        while (condPolicies.hasMoreElements()) {
            ConditionalPolicyMsg condMsg = (ConditionalPolicyMsg) condPolicies.nextElement();
            // if we haven't already subscribed to conditions for this message
            if (!_conditionSubscriptions.contains(condMsg)) {        
                _conditionSubscriptions.addElement(condMsg);
                Vector triggerConditions = condMsg.getTriggerConditions();
                if (triggerConditions != null) {            
                    for (int i=0; i<triggerConditions.size(); i++) {
                        TriggerCondition trigCondition = (TriggerCondition)triggerConditions.elementAt(i);
                        try {
                            TriggerConditionPredicate tcp = new TriggerConditionPredicate(trigCondition);          
                            subscribe(tcp);
                        }
                        catch (ClassNotFoundException ex) {
                            System.err.println("EventTriggerPlugIn: invalid trigger condition in ConditionalPolicyMsg (ClassNotFoundException)"); 
                        }
                    }
                }
            }
        }
    }
    
    /**
     * This method is called when the EventTriggerPlugIn is loaded. It establishes 
     * the subscription for the ConditionalPolicyMsg
     */
    public void setupSubscriptions() {
        _conditionSubscriptions = new Vector();    
        messages_ = (IncrementalSubscription) subscribe(conditionalPolicyMsgPredicate_);
        setupConditionSubscriptions(messages_.elements());

        // should we print debugging info?
        String debug = System.getProperty("SAFE.debug");
        if (debug != null && debug.equalsIgnoreCase("true")) {
            _debug = true;
        }
    }

    /**
     * Called when there is a change on the subscriptions.
     */
    public void execute () {
        if (_debug) System.out.println("ConditionMonitorPlugIn.execute()");
        
        // create a table of current policies
        // key = policy id, value = PolicyMsg
        Iterator currentPolicies = query(policyMsgPredicate_).iterator();
        Hashtable currentPolicyTable = new Hashtable();
        while (currentPolicies.hasNext()) {
            PolicyMsg policyMsg = (PolicyMsg) currentPolicies.next();
            currentPolicyTable.put(policyMsg.getId(), policyMsg);
        }
        
        // setup subscriptions to the trigger conditions of added ConditionalPolicyMessages
        Enumeration added = messages_.getAddedList();
        setupConditionSubscriptions(added);
        
        // remove the policies in effect for each removed ConditionalPolicyMessage
        Collection removed = messages_.getRemovedCollection();
        if (_debug) System.out.println("removed size: " + removed.size());
        Iterator removedIt = removed.iterator();
        while (removedIt.hasNext()) {
            Vector policies = ((ConditionalPolicyMsg) removedIt.next()).getPolicies();
            Vector inEffect = new Vector();
            for (int i=0; i<policies.size(); i++) {
                PolicyMsg policyMsg = (PolicyMsg) policies.elementAt(i);
                if (_debug) {
                    Enumeration enum = currentPolicyTable.keys();
                    System.out.println("current policy table keys: " + currentPolicyTable.keys());
                    while (enum.hasMoreElements()) {
                        System.out.println((String) enum.nextElement());
                    }
                    System.out.println("policyId " + policyMsg.getId());
                }
                if (currentPolicyTable.containsKey(policyMsg.getId())) {
                    inEffect.addElement(policyMsg);
                }
            }
            if (!inEffect.isEmpty()) {
                if (_debug) System.out.println("CondMonPlugIn:: publishing ppu");
                ProposedPolicyUpdate ppu = new ProposedPolicyUpdate(KAoSConstants.REMOVE_POLICIES,
                                                                    inEffect);
                publishAdd(ppu);
            }
        }
        
        // TODO: for efficiency, unsubscribe from tc's of removed policies
        
        // go through all the ConditionalPolicyMessages in effect to check
        // if their trigger conditions are true or false
        Collection inEffect = messages_.getCollection();
        inEffect.removeAll(removed);
        Iterator condPolsIt = inEffect.iterator();
        
        // for each conditional policy
        while (condPolsIt.hasNext()) {
            ConditionalPolicyMsg condMsg = (ConditionalPolicyMsg) condPolsIt.next();
            Vector triggerConditions = condMsg.getTriggerConditions();
            if (triggerConditions != null) {
                boolean evalResult = true;
                if (_debug) System.out.println("ConditionMonitorPlugIn: evaluating conditional policy message:"); 
                // for each trigger condition
                for (int i=0; i<triggerConditions.size(); i++) {
                    boolean thisResult = true;
                    TriggerCondition trigCondition = (TriggerCondition)triggerConditions.elementAt(i);
                    if (_debug) System.out.print(trigCondition.getClassName() + "." 
                                     + trigCondition.getFieldName() + "=="
                                     + trigCondition.getValue() + " ? ");
                    // see if it's true
                    TriggerConditionTruePredicate tctp = new TriggerConditionTruePredicate(trigCondition);                                 
                    Collection c2 = query(tctp);                    
                    if (c2.size() == 0) {
                        // it's false
                        thisResult = false;
                        evalResult = false;
                    }
                    if (_debug) System.out.println(thisResult);
                }
                
                    
                
                // if the evaluation was true, add the policies
                // to the existing policies (if it isn't already
                // in effect)
                if (evalResult) {
                    Vector policies = condMsg.getPolicies();
                    Vector clonedPolicies = new Vector();
                    for (int i=0; i<policies.size(); i++) {
                        PolicyMsg policyMsg = (PolicyMsg) policies.elementAt(i);
                        if (!currentPolicyTable.containsKey(policyMsg.getId())) {
                            // clone the message to prevent a persistence error
                            // whereby an object whose instance is removed
                            // and added again will not be persisted
                            clonedPolicies.addElement(policyMsg.clone());
                        }
                    }
                    if (!clonedPolicies.isEmpty()) {
                        ProposedPolicyUpdate ppu = new ProposedPolicyUpdate(KAoSConstants.ADD_POLICIES,
                                                                            clonedPolicies);
                        publishAdd(ppu);
                    }
                }
                else {
                    // remove the policies from the existing policies
                    // (if it is currently in effect)
                    Vector policies = condMsg.getPolicies();
                    Vector clonedPolicies = new Vector();
                    for (int i=0; i<policies.size(); i++) {
                        PolicyMsg policyMsg = (PolicyMsg) policies.elementAt(i);
                        if (currentPolicyTable.containsKey(policyMsg.getId())) {
                            // clone the message to prevent a persistence error
                            // whereby an object whose instance is removed
                            // and added again will not be persisted
                            clonedPolicies.addElement(policyMsg.clone());
                        }
                    }
                    if (!clonedPolicies.isEmpty()) {
                        ProposedPolicyUpdate ppu = new ProposedPolicyUpdate(KAoSConstants.REMOVE_POLICIES,
                                                                            clonedPolicies);
                        publishAdd(ppu);
                    }
                }
            }
        }        
    }    
} 
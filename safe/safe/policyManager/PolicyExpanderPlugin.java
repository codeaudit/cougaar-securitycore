package safe.policyManager;

import org.cougaar.core.plugin.SimplePlugin;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.util.UnaryPredicate;
import org.w3c.dom.Document;

import java.util.Enumeration;
import java.util.List;
import java.util.HashMap;
import java.util.Vector;
import java.util.Iterator;

import kaos.core.util.*;

import safe.util.*;
	
/**
 * The PolicyExpanderPlugin expands policies before
 * they reach the DomainManagerPlugIn for approval.
 * 
 * It subscribes to UnexpandedPolicyUpdates and UnexpandedConditionalPolicyMsgs.
 * 
 * It publishes ConditionalPolicyMsgs and ProposedPolicyUpdates.
 * 
 * The actual policy expansion happens in the expandPolicy function. Please see
 * the comments for that method for details on how to expand policies.
 */
public class PolicyExpanderPlugin extends SimplePlugin
{
    private UnaryPredicate _unexCondPolicyPredicate = new UnaryPredicate() {
        public boolean execute(Object o) {
        return (o instanceof UnexpandedConditionalPolicyMsg);
        }
        };
    private UnaryPredicate _unexPolicyUpdatePredicate = new UnaryPredicate() {
        public boolean execute(Object o) {
        return (o instanceof UnexpandedPolicyUpdate);
        }
        };

    public void setupSubscriptions()
    {
        _ucpm = (IncrementalSubscription) subscribe(_unexCondPolicyPredicate);
        _upu = (IncrementalSubscription) subscribe (_unexPolicyUpdatePredicate);

        // should we print debugging info?
        String debug = System.getProperty("SAFE.debug");
        if (debug != null && debug.equalsIgnoreCase("true")) {
            _debug = true;
        }
    }
    
    public void execute()
    {
        if (_debug) System.out.println("PolicyExpanderPlugIn::execute()");
        // check for added UnexpandedConditionalPolicyMsgs
        Enumeration ucpmEnum = _ucpm.getAddedList();
        while (ucpmEnum.hasMoreElements()) {
            UnexpandedConditionalPolicyMsg ucpm = (UnexpandedConditionalPolicyMsg) ucpmEnum.nextElement();
            // extract the ConditionalPolicyMsg
            ConditionalPolicyMsg condPolicyMsg = ucpm.getConditionalPolicyMsg();
            // get the policies
            Vector policies = condPolicyMsg.getPolicies();
            Vector newPolicies = new Vector();
            // expand each policy
            for (int i=0; i<policies.size(); i++) {
                PolicyMsg policyMsg = (PolicyMsg) policies.elementAt(i);
                try {                    
                    expandPolicy (policyMsg);
                }
                catch (Exception xcp) {
                    xcp.printStackTrace();
                }                    
            }
            publishRemove (ucpm);
            if (_debug) System.out.println("publishAdd ConditionalPolicyMsg");
            publishAdd (condPolicyMsg);			
        }
        
        // check for added UnexpandedPolicyUpdates
        Enumeration upuEnum = _upu.getAddedList();
        while (upuEnum.hasMoreElements()) {
            UnexpandedPolicyUpdate upu = (UnexpandedPolicyUpdate) upuEnum.nextElement();
            List policies = upu.getPolicies();
            Iterator policyIt = policies.iterator();
            while (policyIt.hasNext()) {
                PolicyMsg policyMsg = (PolicyMsg) policyIt.next();
                try {
                    expandPolicy (policyMsg);
                }
                catch (Exception xcp) {
                    xcp.printStackTrace();
                }
            }
            publishRemove (upu);
            publishAdd (new ProposedPolicyUpdate(upu.getUpdateType(),
                                                 policies));
        }
    }

    /**
     * This function expands a policy.
     * 
     * The original policy should be kept intact, in that no existing fields
     * are removed or changed. You should expand the policy by
     * adding to the original. You may add new attributes, or add new key-value
     * pairs, or add sub-messages to the original policy, whichever way you
     * prefer, as long as the enforcers can parse the additions. The current
     * KAoS infrastructure does not parse these additions so no restrictions
     * are placed on the types of things you add to the original policy.
     * 
     * @param policy	Policy message to expand
     */
    private void expandPolicy (PolicyMsg policyMsg) throws Exception
    {
        /**
        * Example code for NAI
        */
        
        
        // get the attributes of the policy
        Vector attributes = policyMsg.getAttributes();
        // find the XMLContent attribute
        // (assumption: there is only one XMLContent attribute)
        Document xmlContent = null;
        for (int i=0; i<attributes.size(); i++) {
            AttributeMsg attrMsg = (AttributeMsg) attributes.elementAt(i);
            if (attrMsg.getName().equals(XML_KEY)) {
                xmlContent = (Document) attrMsg.getValue();
                break;
            }
        }
        if (xmlContent != null) {
            // INSERT YOUR CODE HERE
            // add to the original policy
            
            // Example of adding an attribute:
            //
            // AttributeMsg newAttrib = new AttributeMsg ("name", "value", true);
            // Note, the attribute name should be unique, or it will overwrite
            // the first attribute found with the same name.
            // policyMsg.setAttribute(newAttrib);
            
            // Example of adding a key-value pair:
            //
            // policyMsg.addSymbol("key", "value");
            
            // Example of adding a subMsg:
            //
            // Msg subMsg = new Msg();
            // policyMsg.addSubMsg("key", subMsg);
        }
        
        return;
    }
        
    private IncrementalSubscription _ucpm;
    private IncrementalSubscription _upu;
    private boolean _debug = false;
    
    public static final String XML_KEY = "XMLContent";
}

package com.nai.security.access;

import java.util.*;
import org.cougaar.core.component.*;


public class TrustAttributeService 
    implements Service, AgentTrustService
{

    /**
     * Unique identfier for this domain of trust buckets. 
     */
    protected String id;

    /**
     * The default set of trust attributes for a set of buckets. 
     */
    protected TrustSet commonSet;

    /**
     * Blackboard object tuples.
     * @see com.nai.security.access.BlackboardObject
     */
    protected Hashtable tuples = new Hashtable();

    /**
     * Construct a new service for the specified Agent, Plugin, or Node.
     * @param id the unique name for agent, etc.
     */
    public TrustAttributeService(String id) 
    {
        this(id, null);
    }

    /**
     * Construct a new service for the specified Agent, Plugin, or Node with
     * the specified TrustSet.
     * @param id unique identifier for this group of trust buckets.
     * @param trust the default trust bucket to use, which may be null.
     */
    public TrustAttributeService(String id, TrustSet trust) 
    {
        this.id = id;
        commonSet = trust;
    }
       
    /**
     * accessor method for the default set of trust attributes.
     * @return the default TrustSet for an Agent.                
     */
    public TrustSet getDefault() {
        return commonSet;
    }

    /**
     * accessor method for the trust set of a previously registered object.
     * @return the explicitly specified set or the default trust set
     */
    public TrustSet getTrustSet(Object obj)
    {
        BlackboardObject set = (BlackboardObject)tuples.get(obj);
	// place access control here
        return set.getTrustSet();
    }

    /**
     * return an iterator over the entire range of trust sets.
     */
    public Iterator getTrustSet()
    {
	//place access control here
        return tuples.values().iterator();

    }

    /**
     * Register a new object with the default trust set.
     */
    public void add(Object obj)
    {
        add(obj, null);  
	//potentially a performance issue this may be removed...
    }
    
    /**
     * Explicitly register a new object and trust set pair with the service. 
     */
    public void add(Object obj, TrustSet trust) 
    {
        tuples.put(obj, new BlackboardObject(obj,trust));
    }


    public void setTrustAttribute(Object obj, TrustAttribute trust)
    {
	//CougaarSecurityManager.checkPermission
	//    (new TrustSetPermission("set"));

	TrustSet set = getTrustSet(obj);
	if(set == null)return;	// maybe throw an exception here
	
	set.addAttribute(trust);
    }

    public TrustAttribute getTrustAttribute(Object obj, String type)
    {
	//CougaarSecurityManager.checkPermission
	//    (new TrustSetPermission("get", "name"));
	TrustSet set = getTrustSet(obj);
	if(set == null)	return null; // maybe throw an exception here?
	return set.getAttribute(type);
    }
    
    /**
     * This inner class creates an enumeration to allow access to 
     * trust attributes. This Iterator should be highly gaurded.
     * @version 1.0
     */
    public class TrustIterator implements Iterator {
     /**
      * The Iterator being encapsulated.
      */
     Iterator i;

     /**
      * Null constructor. This should only be invoked from within 
      * a security subscription. 
      */
     public TrustIterator() { i = tuples.values().iterator(); }

     /**
      * hides the trust attributes and provides backward 
      * compatibility.
      * 
      * @return the next iteration or the default trust set 
      */
     public Object next() {
         TrustSet trust = ((BlackboardObject)i.next()).getTrustSet();
         return (Object)((trust == null)? getDefault(): trust);
         }

     /**
      * delegated to parent's iterator implementation.
      * 
      * @return true if more iterations exist, otherwise false.
      */
     public boolean hasNext() { return i.hasNext();}

     /**
      * delegated to parent's iterator implementation.
      */
     public void remove() { i.remove(); }
   }


}

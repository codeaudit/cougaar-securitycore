/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 * 
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 * </copyright>
 * Created on October 22, 2001, 2:02 PM EDT
 */
package com.nai.security.access;

import org.cougaar.core.society.Message;
import org.cougaar.core.society.MessageEnvelope;

public class AccessControlEnvelope extends MessageEnvelope
{
   /** The added trust set(s) */
    private TrustSet[] set = null;
    
    /**
     * Basic constructor which assumes that a trust set will be set. This 
     * constructor may be deprecated in the future. Use sparingly!!
     */
    public AccessControlEnvelope(Message msg) {
	super(msg);
    }

    /**
     * An envelope for a generic message.
     */
    public AccessControlEnvelope(Message msg, TrustSet set) {
	super(msg);
	this.set = new TrustSet[1];
	this.set[0] = set;
    }

    /**
     * An envelope for a directive message.
     */
    public AccessControlEnvelope(Message msg, TrustSet set[]) {
	super(msg);
	this.set = new TrustSet[set.length];
	for(int i = 0; i < set.length; i++)
	    this.set[i] = set[i];
    }

    /**
     * Public accessor method for the trust set
     * @return the trust set associated with the encapsulated message
     */
    public TrustSet getTrustSet() { return set[0]; }

    /**
     * Public accessor for an array of trust sets. Used with a Directive
     * Message payload.
     * @return an array of trust sets 
     */
    public TrustSet[] getTrustSets() { return set; }

    /**
     * Public modifier method for a signle trust set.
     * @return the trust set associates with the encapsulate message
     */
    public void setTrustSet(TrustSet set) { 
	if(this.set == null)
	    this.set = new TrustSet[1];
	this.set[0] = set;
    }
    
    /**
     * Public modifier method for an array of trust sets. This should be
     * used when the payload is a DirectiveMessage but can be extended to
     * other types of Messages as well.
     * @return an array of trust sets for a message with segmented contents
     */
    public void setTrustSets(TrustSet set[]) {
	this.set = new TrustSet[set.length];
	for(int i = 0; i < set.length; i++)
	    this.set[i] = set[i];
    }

}

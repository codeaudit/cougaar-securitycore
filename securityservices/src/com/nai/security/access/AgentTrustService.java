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

import org.cougaar.core.component.*;

/**
 * An interface to allow Agents and PlugIns limited access to the trust 
 * attribute service. <CODE>TrustAttributes</CODE> are immutable and this 
 * interface ensures that a malicious PlugIn or Agent and cannot replace an 
 * entire <CODE>TrustSet</CODE>.
 */
public interface AgentTrustService extends Service
{
    /**
     * Accessor method for retrieving a trust attribute based on the object
     * and trust attribute (e.g. "IntegrityLevel", "MissionCriticality", etc.)
     * 
     * @see TrustSet
     *
     * @return an immutable trust attribute or null if either object has no 
     * valid trust set or the trust attribute type is not available in the 
     * trust set.
     */
    public TrustAttribute getTrustAttribute(Object obj, String type);

    /**
     * Assignment method for associating the specified trust attribute with 
     * a blackboard object. 
     */
    public void setTrustAttribute(Object obj, TrustAttribute trust);

}
    

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

package org.cougaar.core.security.acl.trust;

import java.io.*;

/**
 * Generic object used to encapsulate objects stored in the 
 * blackboard. Expect further functionality to be added as the
    * blackboard is secured. 
    * 
    * @author Jay Jacobs
    */
public class BlackboardObject implements Serializable
{
    /**
     * The Object to be stored in the blackboard.
     */
    Object obj;
    /**
     *  A trust attribute container for the associated object.
     */
    TrustSet set;

    /**
     * Constructor for an object, trust attribute container pair. 
     * 
     * @param o
     * @param trust
     */
    public BlackboardObject(Object o, TrustSet trust)
    {
        obj = o;
        set = trust;
    }

    /**
     * Public accessor method for the trust attribute container
     * 
     * @return 
     */
    public TrustSet getTrustSet()
    {
        return set;
    }

    /**
     * Public accessor method for the actual object
     * 
     * @return the blackboard object
     */
    public Object getObject()
    {
        return obj;
    }

}

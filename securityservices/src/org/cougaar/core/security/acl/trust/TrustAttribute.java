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

public class TrustAttribute implements Comparable, Serializable
{

    /**
     * The classification type for a trust attribute
     */
    public String name;
    
    /**
     * The classification value of the trust attribute.
     */
    public Object value;


    /**
     * Constructor method with an immutable type. Subclasses may 
     * also restrict access to setting the value or adding a 
     * signature/credential id.
     * 
     * @param name   The meta-name to describe this trust attribute.
     * @param value
     */
    public TrustAttribute(String name, Object value)
    {
        this.name = name;
        this.value = value;
    }

    /**
     * Constructor method for subclasses that either need no 
     * value set or need to override the getName() method for
     * access control.
     * 
     * @param name
     */
    public TrustAttribute(String name) 
    {
        this(name, null);
    }

    public String getName()
    {
        return name;
    }

    public Object getValue()
    {
        return value;
    }

    public String toString() 
    {
        StringBuffer buff = new StringBuffer("[TrustAttribute: ");
        buff.append(getName()).append(" = ").append(getValue().toString());
        buff.append("]");
        return buff.toString();
    }

    /**
     * By default the value object is cloned. This may not be desirable
     * with primitive types and may be overridden by subclasses.
     *
     * @param obj An object representing the value of a trust attribute instance.
     */
    public void setValue(Object obj) {}

    public int compareTo(Object obj) throws ClassCastException
    {
        return 0;
    }
}

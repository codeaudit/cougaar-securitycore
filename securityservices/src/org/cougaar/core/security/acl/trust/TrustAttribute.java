/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 
 
 
 
 
 
 



package org.cougaar.core.security.acl.trust;

import java.io.Serializable;

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

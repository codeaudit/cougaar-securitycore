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

import java.util.Hashtable;
import java.util.Iterator;

public class TrustSet extends Hashtable
{

    public TrustSet()
    {
        super(2);
    }
    
    public TrustAttribute getAttribute(String type) 
    {  
        return (TrustAttribute)get((Object)type);
    }

    public IntegrityAttribute getIntegrityLevel()
    {
        return (IntegrityAttribute)getAttribute(IntegrityAttribute.name);
    }

    public MissionCriticality getMissionCriticality()
    {
        return (MissionCriticality)getAttribute(MissionCriticality.name);
    }

    public void addAttribute(TrustAttribute attribute)
    {
        put((Object)attribute.getName(), (Object)attribute);
    }

    public String toHTML() {
        Iterator i = values().iterator();
        StringBuffer buff = new StringBuffer("<UL>\n");

        while(i.hasNext()) {
            buff.append("<LI>").append((TrustAttribute)i.next()).append("\n");
        }
        buff.append("</UL>\n");
        return buff.toString();
    }

    public String toString() {
        Iterator i = values().iterator();
        StringBuffer buff = new StringBuffer("[TrustSet: ");

        while(i.hasNext()) {
            buff.append(((TrustAttribute)i.next()).toString());
            buff.append(", ");
        }
        buff.append("]");
        return buff.toString();
    }
}

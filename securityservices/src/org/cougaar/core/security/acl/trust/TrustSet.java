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

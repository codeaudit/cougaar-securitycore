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

import org.cougaar.domain.planning.ldm.asset.*; 
import org.cougaar.domain.planning.ldm.plan.*;
import org.cougaar.core.cluster.*;
import org.cougaar.core.plugin.*;
import org.cougaar.core.society.*;
import java.util.*;

public class MessageLog extends Vector
{

    public MessageLog(int size) 
    {
        super(size);
    }


    public void add(Message msg)
    {
        super.add((Object)msg);
    }

    public StringBuffer toHTML(Message msg)
    {
        Directive payload[] = (msg instanceof DirectiveMessage)? 
            ((DirectiveMessage)msg).getDirectives(): null;
//        TrustSet trust = msg.getTrustSet();
        StringBuffer buff = new StringBuffer("<FONT COLOR=\"#FF0000\">Message:</FONT>\n");
        buff.append("\t source = ").append(msg.getOriginator().getAddress());
        buff.append("\t<UL>");
        if(payload != null) {
            for(int i = 0; i < payload.length; i++) {
                                buff.append("<LI>directive[").append(i);
                buff.append("]: source = ").append(payload[i].getSource());
                buff.append(", destination = ").append(payload[i].getDestination());
                if(payload[i] instanceof Task)     {
                    Task t = (Task)payload[i]; 
                    Asset direct = t.getDirectObject();
                    buff.append(", <BR><FONT COLOR=\"#0000FF\">");
                    buff.append(t.getVerb()).append(" task for ");
                    if(direct != null && direct.getUID() != null) {
                        buff.append(direct.getUID().getOwner());
                    }
                    else { buff.append("anonymous"); }
                    buff.append("</FONT>");
                }
                //else { buff.append(" not a Task"); }
                buff.append(", <BR>class = ").append(payload[i].getClass()).append("<BR>\n");
            }
        }                   
        buff.append("\t</UL>");
//        buff.append(trust.toHTML());
        return buff;
    }

    public StringBuffer toOrderedList()
    {
        StringBuffer buff = new StringBuffer();
        Iterator i = iterator();
            
        buff.append("<OL>\n");
        while(i.hasNext()) {                    
            buff.append(toHTML((Message)i.next())).append("\n");
        }                
        buff.append("</OL>\n");
        return buff;
    }                                             
}

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

import java.io.*;
import java.util.*;
import org.cougaar.lib.planserver.*;
import org.cougaar.lib.planserver.psp.*;
import org.cougaar.core.util.*;

public class PSP_AccessControl extends PSP_BaseAdapter 
  implements PlanServiceProvider {
    

    public PSP_AccessControl() { super(); }
 
    public PSP_AccessControl(String pkg, String id) throws RuntimePSPException
    {
        setResourceLocation(pkg, id);
    }

    public boolean returnsHTML() {  return true; }

    public boolean returnsXML() {   return false; }

    public String getDTD() {        return null; }


    public boolean test(HttpInput query_parameters, PlanServiceContext context) {
        super.initializeTest(); // IF subclass off of PSP_BaseAdapter.java
        return false;  // This PSP is only accessed by direct reference.
    }

    public void execute(PrintStream out, HttpInput queryInfo, 
                        PlanServiceContext context, PlanServiceUtilities util) { 
        String agent = context.getServerPlugInSupport().getClusterIDAsString();
	//HybridMTSProxy enforcer = null;
	//PlugInMTSProxy enforcer = MTSProxy.getBinder(agent);
/*    
	out.print("<HTML>\n");
	out.print("<HEAD><TITLE> Message Binder Logging </TITLE></HEAD>\n");
	out.print("<BODY>\n<H1><CENTER> Message Binder Logging for ");
	out.print(agent);
	out.print("</CENTER></H1>\n");
	out.print("<P>Binder for Agent " +  agent + " is " + enforcer + "</P>");
	out.print("<P>URL Parameters: </P>");
	out.print("<UL>");
	Enumeration e = queryInfo.getURLParameters().elements();
	while(e.hasMoreElements()) {
		out.print("<LI>");
		out.println(e.nextElement().toString());
	}

        out.println("</UL>");
	out.println("<P> This enforcer has set aside the following messages: </P>");
        out.println(enforcer.getSetAsideLog().toOrderedList());
	out.println("<P> This enforcer has forwarded the following messages: </P>");
        out.println(enforcer.getForwardLog().toOrderedList());
	out.println("<P> This enforcer has accepted the following messages: </P>");
        out.println(enforcer.getAcceptLog().toOrderedList());                      
        out.println("<P> This enforcer has sent the following messages: </P>");
        out.println(enforcer.getOutgoingLog().toOrderedList());
*/

        out.print("</BODY>\n");
	out.print("</HTML>\n");
    }
}







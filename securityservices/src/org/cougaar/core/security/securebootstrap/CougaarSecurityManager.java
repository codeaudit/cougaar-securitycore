/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Inc
 *  under sponsorship of the Defense Advanced Research Projects
 *  Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS 
 *  PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR 
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF 
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT 
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT 
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL 
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS, 
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR 
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.  
 * 
 * </copyright>
 *
 * CHANGE RECORD
 * - 
 */

package org.cougaar.core.security.securebootstrap;

// Cougaar overlay
import org.cougaar.core.security.constants.IdmefClassifications;

import java.io.*;
import java.net.*;
import java.lang.*;
import java.text.DateFormat;
import java.util.Date;
import java.util.Calendar;
import java.util.Iterator;
import java.util.Vector;
import java.security.Permission;
import java.security.PrivilegedAction;
import java.security.PrivilegedExceptionAction;
import java.security.AccessController;
import java.security.AccessControlContext;
import java.security.PermissionCollection;
import java.security.ProtectionDomain;
import java.security.CodeSource;
import java.security.Principal;

// Needed to retrieve the subject associated with an accessController context
import javax.security.auth.Subject;

/** At the minimum, this security manager requires the following permissions:

    permission java.security.SecurityPermission "getProperty.auth.policy.provider";
    permission java.security.SecurityPermission "getProperty.policy.expandProperties";
    permission java.security.SecurityPermission "getProperty.policy.ignoreIdentityScope";
    permission java.security.SecurityPermission "getProperty.policy.allowSystemProperty";
    permission java.security.SecurityPermission "getProperty.auth.policy.url.1";
    permission java.security.SecurityPermission "getProperty.cache.auth.policy";
    permission java.security.SecurityPermission "getProperty.combiner.provider";
    permission java.security.SecurityPermission "createAccessControlContext";
    permission java.security.SecurityPermission "getDomainCombiner";

    permission javax.security.auth.AuthPermission "getSubjectFromDomainCombiner";
    permission javax.security.auth.AuthPermission "modifyPrincipals";
    permission javax.security.auth.AuthPermission "doAs";
    permission javax.security.auth.AuthPermission "getSubject";
    permission javax.security.auth.AuthPermission "setReadOnly";
    permission javax.security.auth.AuthPermission "getPolicy";

 **/

public class CougaarSecurityManager extends SecurityManager 
{
  private PrintStream auditlog;
  private int debug = 0;
  private EventHolder eventholder=null;
  private String type=null;

  /** The constructor initializes a log file at
      ${COUGAAR_INSTALL_PATH}/log/bootstrap/SecurityManager.log
  **/
  public CougaarSecurityManager() {
    this("");
  }

  public CougaarSecurityManager(String nodeName) {
    // Get name of audit log file
    String sep =  System.getProperty("file.separator", "/");
    // Since multiple nodes may run on the same machine, we need
    // to make sure two nodes will not write to the same log file.
    // Also, log files should not be overwritten each time a
    // node is started again (for forensic purposes).
    Calendar rightNow = Calendar.getInstance();
    String curTime = rightNow.get(Calendar.YEAR) + "-" +
      rightNow.get(Calendar.MONTH) + "-" +
      rightNow.get(Calendar.DAY_OF_MONTH) + "-" +
      rightNow.get(Calendar.HOUR_OF_DAY) + "-" +
      rightNow.get(Calendar.MINUTE);
    String defaultLogName =
      System.getProperty("org.cougaar.install.path", "") +
      sep + "log" + sep + "bootstrap" + sep + "SecurityManager_"
      + nodeName + "_" + curTime + ".log";
    String auditlogname =
      System.getProperty("org.cougaar.core.security.bootstrap.SecurityManagerLogFile",
			 defaultLogName);
    type= IdmefClassifications.SECURITY_MANAGER_EXCEPTION;
    eventholder= EventHolder.getInstance();
    //System.out.println(" Event Holder in Cougaar security mananger got loaded by :"+eventholder.getClass().getClassLoader().toString() );
    //System.out.println("Instance of Event holder in Cougaar security Manger :"+eventholder.toString());
    try {
      auditlog = new PrintStream(new FileOutputStream(auditlogname));
      auditlog.print("<logtime>"+DateFormat.getDateInstance().format(new Date())
		     +"</logtime>\n");
      auditlog.print("<nodeName>"+nodeName+"</nodeName>\n");
    }
    catch (IOException e) {
      System.err.println("Java Security Manager log file not opened properly\n"
			 + e.toString());
    }
    if (debug > 0) {
      System.out.println("Cougaar Security Manager. Logging to " + auditlogname);
    }
    ClassLoader cloader=eventholder.getClass().getClassLoader();
    /* if(cloader!=null)
     System.out.println(" Event Holder in Cougaar security mananger got loaded by :"+cloader.toString() );
    else 
      System.out.println(" Got class loader null for event holder in security manager  :");
    */
  }
   
  public EventHolder getMREventQueue() throws SecurityException {
    if(eventholder!=null){
      return eventholder;
    }
    return null;
  }

  /** throws a security exception if the requested access, specified by
      the given permission, is not permitted based on the security
      policy currently in effect.
      Issue: Defining this method causes a HotSpot Virtual
      Machine Error, Internal Error
  */
  public void checkPermission(Permission perm) {
    Class[] stack = getClassContext();
    try {
      
      // Check that nobody except the KeyRing can read the
      // org.cougaar.core.security.keystore.password properties
      // When Jaas will be patched and fixed, we will have a better solution.
      // This is a temporary solution.
      if (perm instanceof java.util.PropertyPermission) {
	java.util.PropertyPermission p = (java.util.PropertyPermission) perm;
	if (p.getName().equals("org.cougaar.core.security.keystore.password")) {
	  boolean isAllowed = false;
	  Class[] ct = getClassContext();
	  for (int i = 0 ; i < ct.length ; i++) {
	    if (debug > 0) {
	      System.out.println(ct[i].getName());
	    }
	    if (ct[i].getName().equals("org.cougaar.core.security.crypto.KeyRing")) {
	      isAllowed = true;
	      break;
	    }
	  }
	  if (!isAllowed) {
	    throw (new SecurityException("Cannot read org.cougaar.security.keystore.password property"));
	  }
	}
      }
      if (stack.length > 1000) {
	// New security manager class is not on bootstrap classpath.
	// Cause policy to get initialized before we install the new
	// security manager, in order to prevent infinite loops when
	// trying to initialize the policy (which usually involves
	// accessing some security and/or system properties, which in turn
	// calls the installed security manager's checkPermission method
	// which will loop infinitely if there is a non-system class
	// (in this case: the new security manager class) on the stack).
	try {
	  throw new RuntimeException("ERROR: stack overflow");
	}
	catch (Exception exp) {
	  System.out.println("ERROR: stack length=" + stack.length + " - " + exp);
	  exp.printStackTrace();
	}
	throw new SecurityException("JDK error");
      }
      else {
	super.checkPermission(perm);
      }
    } catch (SecurityException e) {
      
      logPermissionFailure(perm, e, stack, true);
      throw (new SecurityException(e.getMessage()));
    }
  }

  /** Display policy information about a particular class
   */
  private void printPolicy(Class c)
  {
    ProtectionDomain pd = c.getProtectionDomain();
    PermissionCollection pc = pd.getPermissions();
    System.out.println("Class: " + c.getName() + "Protection Domain: " + pd.toString());
    System.out.println("Permissions: " + pc.toString());
  }

  /** Log information about a permission failure.
   **/
  private void logPermissionFailure(final Permission perm,
				    final SecurityException e,
				    final Class[] stack,
				    final boolean displaySubject) {
    try {
      System.out.println("Checking permissions for " + perm + " - Exception:"+ e);

    // Could be used to report checkPermission failures to a Monitoring & Response
    // Plugin.
      final String curTime = DateFormat.getDateInstance().format(new Date());
      final AccessControlContext acc = AccessController.getContext();
      final Vector principals=new Vector();
      AccessController.doPrivileged(new PrivilegedAction() {
	  public Object run() {
	    auditlog.print("<securityEvent><securityManagerAlarm><time>"
			   + curTime + "</time><perm>" + perm + "</perm>\n");
	     // Retrieve the subject associated with the current access controller context
	    // See JaasClient to see how to report subject information when logging
	    // security exceptions.
	    
	    if (displaySubject == true) {
	      Subject subj = Subject.getSubject(acc);
	      if (subj != null) {
		Iterator it = subj.getPrincipals().iterator();
		int counter=0;
		while (it.hasNext()) {
		  principals.add((Principal) it.next());
		  auditlog.print("<principal>" + principals.lastElement()  + "</principal>");
		  counter++;
		}
	      }
	    }
	    ByteArrayOutputStream outstream=new ByteArrayOutputStream();
	    e.printStackTrace(new PrintStream(outstream));
	    if(principals.isEmpty())
	      eventholder.addEvent(new BootstrapEvent(type,Calendar.getInstance().getTime(),
						      null,outstream.toString()));  
	    else
	      eventholder.addEvent(new BootstrapEvent(type,Calendar.getInstance().getTime(),
						      (Principal[])principals.toArray(new Principal[0]),outstream.toString()));
	    auditlog.print("<stack>\n");
	    try {
	      outstream.close();
	    }
	    catch (IOException ioexp) {
	      ioexp.printStackTrace();
	    }
	    printStackTrace(e, stack);
	    //e.printStackTrace(auditlog);
	    auditlog.print("</stack></securityManagerAlarm></securityEvent>\n");
	    return null; // nothing to return
	  }
	});
    }
    catch (Exception ex) {
      System.out.println("Unable to log failure");
      ex.printStackTrace();
    }
  }

  private void printStackTrace(Exception e, Class[] stack) {
    StackTraceElement[] ste = e.getStackTrace();
    ProtectionDomain pd = null;
    CodeSource cs = null;
    int j = 0;
    for (int i = 0 ; i < ste.length ; i++) {
      String className = stack[j].getName();
      String location = "";

      if (ste[i].getClassName().equals(className)) {
	// The class array does not have the same number of elements as in the StackTraceElement
	// We need to find a match
	pd = stack[j].getProtectionDomain();
	j++;
      }

      if (pd != null) {
	cs = pd.getCodeSource();
	if (cs != null) {
	  location = cs.getLocation().toString();
	}
      }
      auditlog.println("at " + ste[i].getClassName()
		       + "." + ste[i].getMethodName()
		       + "(" + ste[i].getFileName()
		       + ":" + ste[i].getLineNumber()
		       + ")"
		       + " - " + location);
    }
  }
}

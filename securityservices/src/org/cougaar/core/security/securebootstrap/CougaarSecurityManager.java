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


package org.cougaar.core.security.securebootstrap;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.Constructor;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.CodeSource;
import java.security.DomainCombiner;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.ProtectionDomain;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.Vector;

import javax.security.auth.Subject;
import javax.security.auth.SubjectDomainCombiner;

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

public class CougaarSecurityManager
  extends SecurityManager 
{
  private PrintStream auditlog;
  private int debug = 0;
  private EventHolder eventholder=null;
  private String type=null;
 
  /**
   * cougaar classification name prefix
   */
  private final static String COUGAAR_PREFIX = "org.cougaar.core.security.monitoring.";
  /**
   * security manager exception
   */
  private final static String SECURITY_MANAGER_EXCEPTION = 
    COUGAAR_PREFIX + "SECURITY_MANAGER_EXCEPTION";

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
    type= SECURITY_MANAGER_EXCEPTION;
    eventholder= EventHolder.getInstance();
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
    //ClassLoader cloader=eventholder.getClass().getClassLoader();
  }
   
  public EventHolder getMREventQueue() throws SecurityException {
    if(eventholder!=null){
      return eventholder;
    }
    return null;
  }

  public void checkPermission(Permission perm, Object context) {
    if (context instanceof AccessControlContext) {
      super.checkPermission(perm, context);
      return;
    } 

    if (isSecuredObject(context.getClass().getInterfaces())) {
      // get the class loader of the context object
      ClassLoader loader = context.getClass().getClassLoader();
      final AccessControlContext acc = AccessController.getContext();
      try {
        // set up the parameter types to object the correct constructor
        Class cls = loader.loadClass("org.cougaar.core.security.auth.SecuredObjectPrincipal");
        // NOTE: currently there's only one constructor
        Constructor []constructors = cls.getConstructors();
        // this is the argument to the constructor of SecuredObjectPrincipal
        Object []args = {context};
        // NOTE: assuming one constructor for SecuredObjectPrincipal
        Principal p = (Principal)constructors[0].newInstance(args);
        //Principal p = new SecuredObjectPrincipal((SecuredObject)context);
        Subject subject = new Subject();
        subject.getPrincipals().add(p);
        final DomainCombiner dc = new BothSubjectDomainCombiner(subject);
        
        context = (AccessControlContext)
        AccessController.doPrivileged(new PrivilegedAction() {
      	  public Object run() {
      	    return new AccessControlContext(acc, dc);
      	  }
      	});
      } catch (Exception e) {
        e.printStackTrace(); // this shouldn't happen! (I hope)
      }
    }
    super.checkPermission(perm, context);
  }

  /** throws a security exception if the requested access, specified by
      the given permission, is not permitted based on the security
      policy currently in effect.
      Issue: Defining this method causes a HotSpot Virtual
      Machine Error, Internal Error
  */
  public void checkPermission(Permission perm) {
    /* Get the current execution stack as an array of classes.
     * Note that the array returned by getClassContext() may not
     * have the same length as the array of classes returned by
     * Throwable.getStackTrace() for the security exception thrown by this method.
     * In general, Throwable.getStackTrace() has all the classes from getClassContext()
     * AND additional classes from the JRE, because this method is calling
     * super.checkPermission().
     * However, the stack returned by Throwable.getStackTrace() may not have all the
     * stack frames. Some JVMs are allowed to omit one or more stack frames.
     *
     * Example:
     * java.security.AccessControlContext.checkPermission()
     * java.security.AccessController.checkPermission()
     * java.lang.SecurityManager.checkPermission()
     * org.cougaar.core.security.securebootstrap.CougaarSecurityManager.checkPermission()
     * ...
     * Stack bottom
     *
     * getClassContext() will return an array containing everything between
     * Stack bottom and CougaarSecurityManager.
     *
     */
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
      	  System.out.println("ERROR: stack length=" + stack.length + " - " + perm);
      	  exp.printStackTrace();
      	}
      	throw new SecurityException("JDK error");
        }
        else {
  	      super.checkPermission(perm);
        }
      } catch (SecurityException e) {
        if(!isBlackboardPermission(perm)) { 
          logPermissionFailure(perm, e, stack, true);
        }
        throw (new SecurityException(e.getMessage()));
      }
  }

  // check if the array of classes is an instance of SecuredObject
  private boolean isSecuredObject(Class []cls) {
    for(int i = 0; i < cls.length; i++) {
      // can't use instanceof since SecuredObject is loaded by Cougaar's ClassLoader
      // and not the System's ClassLoader      
      if (cls[i].getName().equals("org.cougaar.core.security.auth.SecuredObject")) {
        return true;
      } 
    } 
    return false;
  }
  
  private boolean isBlackboardPermission(Permission p) {
    // can't use instanceof since SecuredObject is loaded by Cougaar's ClassLoader
    // and not the System's ClassLoader      
    Class superClass = p.getClass().getSuperclass();
    if (superClass.getName().equals("org.cougaar.core.security.auth.ServicePermission")) { 
      return true;
    } 
    return false;
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
      //System.out.println("Logging permission failure for " + perm + " - Exception:"+ e);

      // Could be used to report checkPermission failures to a Monitoring & Response
      // Plugin.
      final AccessControlContext acc = AccessController.getContext();
      final Vector principals=new Vector();
      AccessController.doPrivileged(new PrivilegedAction() {
	  public Object run() {
	    // Calling DateFormat.getDateInstance() may require specific
	    // privileges. In particular, access to packages under sun.text.
	    // may be required.
	    String curTime = DateFormat.getDateInstance().format(new Date());
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
	    try {
	      if(principals.isEmpty()) {
		eventholder.addEvent(
		  new BootstrapEvent(type,Calendar.getInstance().getTime(),
				     null,outstream.toString()));  
	      }
	      else {
		eventholder.addEvent(
		  new BootstrapEvent(type,Calendar.getInstance().getTime(),
				     (Principal[])principals.toArray(new Principal[0]),
				     outstream.toString()));
	      }
	    }
	    catch (Exception e) {
	      auditlog.print("<IDMEF>Unable to publish IDMEF event. Reason:" + e + "<IDMEF>");
	      e.printStackTrace(auditlog);
	    }

	    auditlog.print("<stack>\n");
	    try {
	      outstream.close();
	    }
	    catch (IOException ioexp) {
	      ioexp.printStackTrace();
	    }
	    printStackTrace(e, stack, perm);
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

  /** Print the stack trace
   * In addition to what the VM usually prints (method name, file name, line number) when
   * an exception is thrown, this method attempts to print the jar file and whether
   * the jar file had the privilege to perform the operation.
   * Not all VMs return the same information, so this may not work on all VMs.
   */
  private void printStackTrace(Exception secexp, Class[] stack, Permission perm) {
    StackTraceElement[] ste = secexp.getStackTrace();

    // First, build a list of StackTraceElement and Class.
    // The class array does not have the same number of elements as in the StackTraceElement
    ArrayList stackElements = new ArrayList(ste.length);
    int stackIndex = stack.length - 1;
    int stackTraceIndex = ste.length - 1;
    boolean modifyStackIndex;
    boolean isNative;

    while ((stackIndex >= 0) && (stackTraceIndex >= 0)) {
      StackElementAndClass element = new StackElementAndClass();
      element.canDo = null;
      modifyStackIndex = false;
      isNative = false;
      if ((stackTraceIndex >= 0) && ste[stackTraceIndex].isNativeMethod()) {
	isNative = true;
      }
      if ((stackIndex >= 0) && !isNative) {
	// The SUN VM does not include native methods in the getStackContext()
	element.stackClassElement = stack[stackIndex];
	element.protectionDomain = element.stackClassElement.getProtectionDomain();
	element.canDo = Boolean.valueOf(hasPrivileges(element.protectionDomain, perm));
	modifyStackIndex = true;
      }	
      if (stackTraceIndex >= 0) {
	if ((stackIndex < 0) ||
	    isNative ||
	    ((stackIndex >= 0) &&
	     ste[stackTraceIndex].getClassName().equals(stack[stackIndex].getName()))) {
	  // Some frames may be missing in the Throwable.getStackElements(),
	  // according to the Java doc.
	  element.stackTraceElement = ste[stackTraceIndex];
	  stackTraceIndex--;
	}
      }
      if ((stackIndex >= 0) && modifyStackIndex) {
	stackIndex--;
      }

      stackElements.add(0, element);
    }

    boolean logProtectionDomain = false;
    boolean isFirstExceptionDone = false;

    // Loop through all stack elements and display information about each class
    Iterator it = stackElements.iterator();
    while (it.hasNext()) {
      StackElementAndClass element = (StackElementAndClass) it.next();
      logProtectionDomain = false;
      if (element.canDo == Boolean.FALSE && !isFirstExceptionDone) {
	isFirstExceptionDone = true;
	logProtectionDomain = true;
      }
      logStackElement(element, logProtectionDomain);
    }
    /*
    auditlog.print("\n");
    auditlog.print("\n");
    secexp.printStackTrace(auditlog);

    auditlog.print("\n");
    auditlog.print("\n");
    for (int i = 0 ; i < stack.length ; i++) {
      auditlog.print(stack[i].getName() + "\n");
    }
    */
  }

  private void logStackElement(StackElementAndClass stackElement,
			       boolean logProtectionDomain) {
    String classUrl = "unknown location";
    if (stackElement.protectionDomain != null) {
      CodeSource cs = stackElement.protectionDomain.getCodeSource();
      if (cs != null && cs.getLocation() != null) {
	classUrl = cs.getLocation().toString();
      }
    }

    String className = "";
    String methodName = "";
    String fileName = "";
    int lineNumber = 0;
    boolean isNative = false;

    if (stackElement.stackClassElement != null) {
      className = stackElement.stackClassElement.getName();
      if (stackElement.stackTraceElement != null &&
	  !className.equals(stackElement.stackTraceElement.getClassName())) {
	System.err.println("Security Manager: Inconsistent stack frames");
      }
    }
    if (stackElement.stackTraceElement != null) {
      className = stackElement.stackTraceElement.getClassName();
      methodName = stackElement.stackTraceElement.getMethodName();
      fileName = stackElement.stackTraceElement.getFileName();
      lineNumber = stackElement.stackTraceElement.getLineNumber();
      isNative = stackElement.stackTraceElement.isNativeMethod();
    }

    String logString = "at " + className;
    if (stackElement.stackTraceElement != null) {
      logString = logString + "." + methodName;
      if (isNative) {
	logString = logString + "(Native method)";
      }
      else {
	logString = logString + "(" + fileName
	  + ":" + lineNumber
	  + ")";
      }
    }
    logString = logString + "\n     from " + classUrl + " ";

    if (stackElement.canDo == null) {
      logString = logString + "(??)";
    }
    else if (stackElement.canDo == Boolean.TRUE) {
      logString = logString + "(OK)";
    }
    else {
      logString = logString + "(NOK)";
    }

    if (logProtectionDomain && stackElement.protectionDomain != null) {
      logString = logString + "\n" + stackElement.protectionDomain.toString();
    }
    auditlog.println(logString);
  }

  private boolean hasPrivileges(ProtectionDomain pd, Permission perm) {
    if (pd != null &&  !pd.implies(perm)) {
      return false;
    }
    return true;
  }

  private class StackElementAndClass {
    public StackTraceElement stackTraceElement;
    public Class stackClassElement;
    public Boolean canDo = null;
    public ProtectionDomain protectionDomain = null;
  }

  private static class BothSubjectDomainCombiner
    extends SubjectDomainCombiner {
    public BothSubjectDomainCombiner(Subject subject) {
      super(subject);
    }
    
    public ProtectionDomain[] combine(ProtectionDomain[] currentDomains, 
                                      ProtectionDomain[] assignedDomains) {
      if (assignedDomains != null) {
        assignedDomains = super.combine(assignedDomains, null);
      }
      return super.combine(currentDomains, assignedDomains);
    }
  }
}

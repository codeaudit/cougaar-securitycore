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
import java.net.URL;
import java.text.DateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

public class SecurityLogImpl
extends BaseSingleton
implements SecurityLog
{
  private PrintStream _log;
  private EventHolder _eventholder=null;
  private String _type=null;

  /**
   * cougaar classification name prefix
   */
  private final static String COUGAAR_PREFIX =
  "org.cougaar.core.security.monitoring.";

  /**
   * jar verification failure
   */
  private final static String JAR_VERIFICATION_FAILURE = 
  COUGAAR_PREFIX + "JAR_VERIFICATION_FAILURE";

  /** The set of URLs that cannot be used because of security issues.
   */
  private static Set _badUrls = new HashSet();

  private static final Logger _logger = Logger.getInstance();

  protected SecurityLogImpl()
    {
      _type=JAR_VERIFICATION_FAILURE;
      _eventholder=EventHolder.getInstance();
    }
  
  private static SecurityLog _jarVerificationLog;

  public static SecurityLog getInstance() {
    _jarVerificationLog = (SecurityLog)
      getInstance(SecurityLogImpl.class,
		  SecurityLog.class,
		  _jarVerificationLog);
    return _jarVerificationLog;
  }

  public void createLogFile(String nodeName) {

    // Get name of the log file
    
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
      sep + "log" + sep + "bootstrap" + sep + "JarVerification_"
      + nodeName + "_" + curTime + ".log";
    String logname =
      System.getProperty("org.cougaar.core.security.bootstrap.JarVerificationLogFile",
			 defaultLogName);

    _logger.debug("Creating Jar Verification Log " + logname);

    try {
      _log = new PrintStream(new FileOutputStream(logname));
      _log.print("<logtime>"+
                 DateFormat.getDateInstance().format(new Date())+
                 "</logtime>\n");
      _log.print("<nodeName>"+nodeName+"</nodeName>\n");
    }
    catch (IOException e) {
      System.err.println("Jar verification log file not opened properly\n"
			 + e.toString());
    }
  }
  
  /** Logs exceptions of type java.security.GeneralSecurityException and 
   *    java.lang.SecurityException 
   */
  public void logJarVerificationError(URL url, Exception e) {
    /* Could be used to report jar file verification exceptions
     * to a Monitoring & Response Plugin. */
    if (!_badUrls.contains(url)) {
      logException(e);
      if (url != null) {
       	_badUrls.add(url);
      }
    }
    // Do not log. The event has already been logged.
  }

  private ByteArrayOutputStream outstream=new ByteArrayOutputStream();

  private void logException(Exception e) {
    if (_log != null) {
      String curTime = DateFormat.getDateInstance().format(new Date());
      _log.print("<securityEvent><time>" + curTime + "</time>");
      _log.print("\n" + e.getMessage());
      if (e.getCause() != null) {
	_log.print("\n" + e.getCause().getMessage());
      }
      _log.print("\n<stack>\n");
      e.printStackTrace(_log);
      _log.print("</stack></securityEvent>\n");
      synchronized(outstream) {
        outstream.reset();
        e.printStackTrace(new PrintStream(outstream));
      }
      _eventholder.addEvent
	(new BootstrapEvent(_type,Calendar.getInstance().getTime(),
			    null,outstream.toString()));
    }
    else {
      _logger.warn("Unable to log JAR file verification error:" + e);
    }
  }

}


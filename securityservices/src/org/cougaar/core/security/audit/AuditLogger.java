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
 
 
 
 
 
 



package org.cougaar.core.security.audit;


import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;

import org.apache.catalina.realm.GenericPrincipal;
import org.cougaar.util.log.LoggerFactory;


/**
 * Logs access to Component Resources within Cougaar, and the web.  The System
 * property <b>org.cougaar.core.security.audit</b> identifies whether to log
 * audit requests.  The System property
 * <b>org.cougaar.core.security.audit.outputdir</b> identifies the directory
 * to create the audit log file(s) in.  By default the  directory will be the
 * <b>org.cougaar.install.path/auditlogs/</b> directory. The argument
 * <b>org.cougaar.core.security.audit.properties</b> identifies the location
 * of the webaudit.properties file used to identify  the users/roles to audit.
 * When security is enabled you need to had the following permissions to the
 * Cougaar_Java.policy:     permission java.util.logging.LoggingPermission
 * "control"; permission java.io.FilePermission
 * "${org.cougaar.install.path}${/}workspace${/}auditlogs${/}", "write,read";
 * permission java.lang.RuntimePermission
 * "accessClassInPackage.sun.util.logging.resources";
 *
 * @author ttschampel
 */
public class AuditLogger {
  private static Map loggers = new HashMap();
  private static boolean auditEnabled = false;
  private static String auditLogDirectory = System.getProperty(
      "org.cougaar.workspace") + File.separatorChar + "audit";
  private static Map roleMap = new HashMap();
  private static Map userMap = new HashMap();
  /** Size limit in bytes of a log file */
  private static final int LIMIT = 1000000;
  /** count Number of ouput files to cycle through */
  private static final int COUNT = 5;
  /** Whether to append to existing log files */
  private static final boolean APPEND = false;
  private static org.cougaar.util.log.Logger auditLogger = LoggerFactory.getInstance()
                                                                        .createLogger(AuditLogger.class);

  /**
   * Check if auditing is enabled and find the auditlogs directory
   */
  static {
    String str = System.getProperty("org.cougaar.core.security.audit");
    if ((str != null) && str.toUpperCase().equals("TRUE")) {
      auditEnabled = true;
    }

    if (auditLogger.isDebugEnabled()) {
      auditLogger.debug("Configuring AuditLogger. Audit enabled: "
        + auditEnabled);
    }


    if (auditEnabled) {
      str = System.getProperty("org.cougaar.core.security.audit.outputdir");
      if (str != null) {
        auditLogDirectory = str;
      } else {
        str = System.getProperty("org.cougaar.workspace");
        if (str == null) {
          if (auditLogger.isWarnEnabled()) {
            auditLogger.warn("org.cougaar.workspace not specified");
          }

          auditLogDirectory = "";
        } else {
          auditLogDirectory = str + File.separator + "auditlogs"
            + File.separator;
          File dir = new File(auditLogDirectory);
          if (!dir.exists()) {
            dir.mkdir();
          }
        }
      }

      str = System.getProperty("org.cougaar.core.security.audit.properties");
      if (str != null) {
        Properties p = new Properties();
        try {
          p.load(new FileInputStream(str));
          Set keySet = p.keySet();
          Iterator iter = keySet.iterator();
          while (iter.hasNext()) {
            String key = (String) iter.next();
            String value = p.getProperty(key);
            if (value.toUpperCase().equals("TRUE")) {
              if (key.startsWith("user.")) {
                userMap.put(key.substring(key.indexOf(".") + 1, key.length()),
                  new Boolean(true));
              } else if (key.startsWith("role.")) {
                roleMap.put(key.substring(key.indexOf(".") + 1, key.length()),
                  new Boolean((true)));
              }
            }
          }
        } catch (Exception pe) {
          if (auditLogger.isErrorEnabled()) {
            auditLogger.error("Can't process properties file " + str, pe);
          }
        }
      }

      if (auditLogger.isInfoEnabled()) {
        auditLogger.info("Audit logs stored in directory:" + auditLogDirectory);
      }
    }
  }

  /**
   * Blank constructor to prevent construction of this class
   */
  private AuditLogger() {
  }

  /**
   * Retrieve the audit logging directory
   *
   * @return
   */
  public static String getLoggingDirectory() {
    return auditLogDirectory;
  }


  /**
   * Create a Logger to Audit access to a service
   *
   * @param resource Name of Resource or Service
   */
  private static void createServiceLogger(String resource) {
    if (!auditEnabled) {
      return;
    }

    Logger logger = Logger.getLogger(resource);
    FileHandler serviceFileHandler = null;

    try {
      String fileName = "Logging-"
        + System.getProperty("org.cougaar.node.name") + ".txt";
      serviceFileHandler = new FileHandler(auditLogDirectory + resource
          + fileName, LIMIT, COUNT, APPEND);
      serviceFileHandler.setFormatter(new ServiceAuditXMLFormatter());

    } catch (SecurityException e) {
      auditLogger.warn(resource + e.getLocalizedMessage(), e);
    } catch (IOException e) {
      auditLogger.warn(resource + e.getLocalizedMessage(), e);
    }

    if (serviceFileHandler != null) {
      logger.addHandler(serviceFileHandler);
    }

    logger.setUseParentHandlers(false);
    logger.setLevel(Level.ALL);
    auditLogger.info(resource + " initialized");
    loggers.put(resource, "TRUE");
  }


  /**
   * Create a Logger to Log Audit events for Tomcat
   */
  private static void createWebLogger() {
    if (!auditEnabled) {
      return;
    }

    Logger logger = Logger.getLogger("WebLogger");
    FileHandler webFileHandler = null;
    try {
      String fileName = "WebLog-" + System.getProperty("org.cougaar.node.name")
        + ".txt";
      webFileHandler = new FileHandler(auditLogDirectory + fileName, LIMIT,
          COUNT, APPEND);
      webFileHandler.setFormatter(new WebAuditXMLFormatter());
    } catch (SecurityException e) {
      auditLogger.warn("WebLogger" + e.getLocalizedMessage(), e);
    } catch (IOException e) {
      auditLogger.warn("WebLogger" + e.getLocalizedMessage(), e);
    }

    if (webFileHandler != null) {
      logger.addHandler(webFileHandler);
    }

    logger.setUseParentHandlers(false);
    logger.setLevel(Level.ALL);
    if(auditLogger.isInfoEnabled()) {
      auditLogger.info("WebLogger initialized");
    }
    loggers.put("WebLogger", "TRUE");

  }


  /**
   * Log audit for a service
   *
   * @param agent Name of agent
   * @param resource Classname of resource
   * @param client Classname of client
   */
  public static void logServiceEvent(String agent, String resource,
    String client) {
    if (auditEnabled) {
      if (loggers.get(resource) == null) {
        createServiceLogger(resource);
      }

      Logger logger = Logger.getLogger(resource);
      if (logger.isLoggable(Level.INFO)) {
        logger.info(agent + ";" + resource + ";" + client);
      }
    }
  }


  /**
   * Log successfull access to a web resource
   *
   * @param request The HTTPServletRequest
   * @param servletName The servletName that is accessed
   * @param agent Name of the agent
   */
  public static void logWebEvent(HttpServletRequest request,
    String servletName, String agent) {
    if (!auditEnabled) {
      return;
    }

    if (loggers.get("WebLogger") == null) {
      createWebLogger();
    }

    Logger logger = Logger.getLogger("WebLogger");
    if (logger.isLoggable(Level.INFO)) {
      GenericPrincipal gp = (GenericPrincipal) request.getUserPrincipal();
      String[] roles = null;
      String username = null;
      if (gp != null) {
        username = gp.getName();
        roles = gp.getRoles();
      }

      String authType = request.getAuthType();


      boolean logIt = false;
      boolean containsRole = false;
      if (roles != null) {
        for (int r = 0; r < roles.length; r++) {
          if (roleMap.containsKey(roles[r])) {
            containsRole = true;
            break;
          }
        }
      }
      String roleList = "";
      if (roles != null  && roles.length >= 1) {
        for (int r = 0; r < roles.length; r++) {
          roleList += ";" + roles[r];
        }
      }

      if ((roleMap.size() == 0) && (userMap.size() == 0)) {
        logIt = true;
      } else {
        if ((roleMap.size() == 0) && (userMap.get(username) != null)) {
          logIt = true;
        } else if ((userMap.size() == 0) && containsRole) {
          logIt = true;
        } else if ((userMap.get(username) != null) && containsRole) {
          logIt = true;
        }
      }

      if (logIt || ((username == null) && (roles == null))) {
        logger.info(agent + ";" + authType + ";" + username
                    + ";" + request.getRemoteAddr() + 
                    ";" + request.getServerName() + ";" + servletName
                    + roleList);
      }
    }
  }
}

/*
 * <copyright>
 *  Copyright 2000-2003 Cougaar Software, Inc.
 *  All Rights Reserved
 * </copyright>
 */


/*
 * Created on Jul 16, 2003
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package org.cougaar.core.security.audit;


import javax.servlet.http.HttpServletRequest;

import org.apache.catalina.realm.GenericPrincipal;

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


/**
 * Logs access to Component Resources within Cougaar, and the web.  The System
 * property <b>org.cougaar.core.security.audit</b> identifies whether to log
 * audit requests.  The System property
 * <b>org.cougaar.core.security.audit.outputdir</b> identifies the directory
 * to create the audit log file(s) in.  By default the  directory will be the
 * <b>org.cougaar.install.path/auditlogs/</b> directory. The argument
 * <b>org.cougaar.core.security.audit.properties</b> identifies the location
 * of the webaudit.properties file used to identify  the users/roles to audit.
 *
 *When security is enabled you need to had the following permissions to
 *the Cougaar_Java.policy:
 *	permission java.util.logging.LoggingPermission "control";
 * 	permission java.io.FilePermission "${org.cougaar.install.path}${/}workspace${/}auditlogs${/}*", "write,read";
 *	permission java.lang.RuntimePermission "accessClassInPackage.sun.util.logging.resources";
 *
 *
 * @author ttschampel
 */
public class AuditLogger {
    private static Map loggers = new HashMap();
    private static boolean auditEnabled = false;
    private static String auditLogDirectory = "";
    private static Map roleMap = new HashMap();
    private static Map userMap = new HashMap();

    /**
     * Check if auditing is enabled and find the auditlogs directory
     */
    static {
        String str = System.getProperty("org.cougaar.core.security.audit");
        if ((str != null) && str.toUpperCase().equals("TRUE")) {
            auditEnabled = true;
        }

        if (auditEnabled) {
            str = System.getProperty(
                    "org.cougaar.core.security.audit.outputdir");
            if (str != null) {
                auditLogDirectory = str;
            } else {
                str = System.getProperty("org.cougaar.install.path");
                if (str == null) {
                    System.err.println("cougaar install path not specified");
                    auditLogDirectory = "";
                } else {
                    auditLogDirectory = System.getProperty(
                            "org.cougaar.install.path") + File.separator
                        + "auditlogs" + File.separator;
                    File dir = new File(auditLogDirectory);
                    if (!dir.exists()) {
                        dir.mkdir();
                    }
                }
            }

            str = System.getProperty(
                    "org.cougaar.core.security.audit.properties");
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
                                userMap.put(key.substring(key.indexOf(".") + 1,
                                        key.length()), new Boolean(true));
                            } else if (key.startsWith("role.")) {
                                roleMap.put(key.substring(key.indexOf(".") + 1,
                                        key.length()), new Boolean((true)));
                            }
                        }
                    }
                } catch (Exception pe) {
                    System.err.println("Can't process properties file " + str);
                    pe.printStackTrace();
                }
            }
        }

        System.out.println("Audit logs stored in directory:"
            + auditLogDirectory);
    }

    /**
     * Blank constructor to prevent construction of this class
     */
    private AuditLogger() {
    }

    /**
     * Create a Logger to Audit access to a service
     *
     * @param resource Name of Resource or Service
     */
    private static void createServiceLogger(String resource) {
        Logger logger = Logger.getLogger(resource);
        FileHandler serviceFileHandler = null;

        try {
            serviceFileHandler = new FileHandler(auditLogDirectory + resource
                    + "Logging.txt");
            serviceFileHandler.setFormatter(new ServiceAuditXMLFormatter());

        } catch (SecurityException e) {
            logger.warning(resource + e.getLocalizedMessage());
            e.printStackTrace();
        } catch (IOException e) {
            logger.warning(resource + e.getLocalizedMessage());
            e.printStackTrace();
        }

        if (serviceFileHandler != null) {
            logger.addHandler(serviceFileHandler);
        }

        logger.setLevel(Level.ALL);
        logger.info(resource + " initialized");
        loggers.put(resource, "TRUE");
    }


    /**
     * Create a Logger to Log Audit events for Tomcat
     */
    private static void createWebLogger() {
        Logger logger = Logger.getLogger("WebLogger");
        FileHandler webFileHandler = null;
        try {
            webFileHandler = new FileHandler(auditLogDirectory + "WebLog.txt");
            webFileHandler.setFormatter(new WebAuditXMLFormatter());
        } catch (SecurityException e) {
            logger.warning("WebLogger" + e.getLocalizedMessage());
            e.printStackTrace();
        } catch (IOException e) {
            logger.warning("WebLogger" + e.getLocalizedMessage());
            e.printStackTrace();
        }

        if (webFileHandler != null) {
            logger.addHandler(webFileHandler);
        }

        logger.setLevel(Level.ALL);
        logger.info("WebLogger initialized");
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
                logger.info(agent + ";" + authType + ";" + username + ";"
                    + roles + ";" + request.getRemoteAddr() + ";"
                    + request.getServerName() + ";" + servletName);
            }
        }
    }
}

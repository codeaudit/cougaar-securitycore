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

package org.cougaar.core.security.acl.user;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.io.FileNotFoundException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.cougaar.core.security.crypto.ldap.admin.UserAdminServlet;
import org.cougaar.core.security.crypto.ldap.KeyRingJNDIRealm;
import org.cougaar.core.security.services.acl.UserServiceException;
import org.cougaar.core.util.UID;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;
import org.xml.sax.SAXException;

import org.cougaar.util.ConfigFinder;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

/**
 * @author srosset
 *
 * This class reads and writes the user database from/to an XML file.
 */
public class UserFileParser {
  private static Logger    _log;
  private String           _domain;
  private UserEntries      _userCache;
  
  static {
    _log = LoggerFactory.getInstance().createLogger(UserAdminServlet.class);
  }

  public static final String ROLE_ASSIGNMENT = "role";

  public UserFileParser(UserEntries userCache) {
    init(userCache);
  }

  public UserFileParser() {
  }
  
  private void init(UserEntries userCache) {
    _userCache = userCache;
    _domain = _userCache.getDomain();
    if (_domain == null) {
      String s = "User domain should not be null";
      if (_log.isWarnEnabled()) {
        _log.warn(s);
      }
      throw new IllegalArgumentException(s);
    }
  }
  
  public void readUsers() {
    String fileName = "UserFile-" + _domain + ".xml";
    readUsers(fileName);
  }
  
  public void readUsers(String fileName) {
    try {
      InputStream userIs = ConfigFinder.getInstance().open(fileName);
      if (userIs != null) {
        if (_log.isInfoEnabled()) {
          _log.info("Reading users file...");
        }
        readUsers(userIs);
      } else {
        if (_log.isInfoEnabled()) {
          _log.info("UserFile.xml does not exist -- no users or role");
        }
      }
    } catch (Exception e) {
      if (_log.isWarnEnabled()) {
        _log.warn("Couldn't load users from file: ", e);
      }
    }
  }
  
  private void printField(PrintStream ps, Map m, String field) {
    Object val = m.get(field);
    if (UserEntries.FIELD_ROLE_LIST.equals(field)) {
      if (val != null) {
        Iterator it = ((Set)val).iterator();
        while (it.hasNext()) {
          ps.println("    <role>" + it.next() +
              "</role>");
        }
      }
    }
    else {
      if (val == null) {
        val = "";
      }
      ps.println("    <" + field + ">" + val
        + "</" + field + ">");
    }
  }
  
  public void saveUsersAndRoles(OutputStream os) {
    PrintStream ps = new PrintStream(os);
    ps.println("<?xml version='1.0' encoding='ISO-8859-1'?>");
    ps.println("<userdata>");
    ps.println("  <password>");
    ps.println("    <" + UserEntries.FIELD_IS_CLEAR_TEXT_PASSWORD +
        ">false</" + UserEntries.FIELD_IS_CLEAR_TEXT_PASSWORD + ">");
    ps.println("  </password>");
    saveUsers(ps);
    saveRoles(ps);
    ps.println("</userdata>");
  }
  
  private void saveRoles(PrintStream ps) {
    Set s = null;
    try {
      s = _userCache.getRoles(0);
    }
    catch (UserServiceException e) {
      _log.warn("Unable to get roles", e);
    }
    if (s != null) {
      Iterator it = s.iterator();
      while (it.hasNext()) {
        Map m = null;
        try {
          m = _userCache.getRole((String)it.next());
        }
        catch (UserServiceException e) {
          _log.warn("Unable to get role ID", e);
        }
        if (m != null) {
          ps.println("  <role>");
          printField(ps, m, UserEntries.FIELD_RID);
          printField(ps, m, UserEntries.FIELD_DESCRIPTION);
          ps.println("  </role>");
        }
      }
    }
  }
  
  private void saveUsers(PrintStream ps) {
    Set s = _userCache.getUsers(0);
    Iterator it = s.iterator();
    while (it.hasNext()) {
      String uid = (String) it.next();
      Map m = null;
      try {
        m = _userCache.getUser(uid);
      }
      catch (UserServiceException e) {
        _log.warn("Unable to get user data", e);
      }
      if (m != null) {
        ps.println("  <user>");
        printField(ps, m, UserEntries.FIELD_UID);
        printField(ps, m, UserEntries.FIELD_PASSWORD);
        printField(ps, m, UserEntries.FIELD_ENABLE_TIME);
        printField(ps, m, UserEntries.FIELD_CERT_OK);
        printField(ps, m, UserEntries.FIELD_AUTH);
        printField(ps, m, UserEntries.FIELD_FNAME);
        printField(ps, m, UserEntries.FIELD_LNAME);
        printField(ps, m, UserEntries.FIELD_NAME);
        printField(ps, m, UserEntries.FIELD_MAIL);
        printField(ps, m, UserEntries.FIELD_ROLE_LIST);
        
        ps.println("  </user>");
      }
    }
  }
  
  /**
   * Loads a database of users from an XML file.
   * @param in - the InputStream containing the XML user file.
   */
  public void readUsers(InputStream in) {
    try {
      DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
      DocumentBuilder db = dbf.newDocumentBuilder();
      Document doc = db.parse(in);
      Element rootElement = doc.getDocumentElement();
      NodeList nodes = rootElement.getChildNodes();
      HashMap userAssigns = new HashMap();
      HashMap roleAssigns = new HashMap();
      boolean isClearTextPassword = true;
      for (int i = 0; i < nodes.getLength(); i++) {
        Node item = nodes.item(i);
        if (item instanceof Element) {
          Element l = (Element) item;
          Map map = readMap(l);
          Set groups = (Set) map.remove(ROLE_ASSIGNMENT);
          if ("user".equals(l.getNodeName())) {
            String pwd = (String) map.get(UserEntries.FIELD_PASSWORD);
            String user = (String) map.get(UserEntries.FIELD_UID);
            if (user == null) {
              _log.warn("No id for user entry");
              continue;
            }
            if (_log.isDebugEnabled()) {
              _log.debug("Adding user " + user + " with password:"
                  + pwd);
            }
            if (isClearTextPassword && pwd != null) {
              pwd = KeyRingJNDIRealm.encryptPassword(_domain + "\\" + user, 
                                                     pwd);
            }
            map.put(UserEntries.FIELD_PASSWORD,pwd);
            _userCache.addUser(user, map);
            if (groups != null) {
              userAssigns.put(user, groups);
            }
          } else if ("role".equals(l.getNodeName())) {
            String role = (String) map.get(UserEntries.FIELD_RID);
            if (role == null) {
              if (_log.isWarnEnabled()) {
                _log.warn("No id for role entry");
              }
              continue;
            }
            _userCache.addRole(role, map);
            if (groups != null) {
              roleAssigns.put(role, groups);
            }
          } else if ("password".equals(l.getNodeName())) {
            String isClearText = (String)
                map.get(UserEntries.FIELD_IS_CLEAR_TEXT_PASSWORD);
            if (isClearText != null) {
              isClearTextPassword = Boolean.getBoolean(isClearText);
            }
          }
        }
      }
      Iterator assigns = userAssigns.entrySet().iterator();
      while (assigns.hasNext()) {
        Map.Entry entry = (Map.Entry) assigns.next();
        String user = (String) entry.getKey();
        Iterator iter = ((Set) entry.getValue()).iterator();
        while (iter.hasNext()) {
          String group = (String) iter.next();
          _userCache.assign(user, group);
        }
      }
      assigns = roleAssigns.entrySet().iterator();
      while (assigns.hasNext()) {
        Map.Entry entry = (Map.Entry) assigns.next();
        String role = (String) entry.getKey();
        Iterator iter = ((Set) entry.getValue()).iterator();
        while (iter.hasNext()) {
          String group = (String) iter.next();
          _userCache.addRoleToRole(role, group);
        }
      }
    } catch (ParserConfigurationException e) {
      _log.warn("Cannot parse user file: ", e);
    } catch (UserServiceException e) {
      _log.warn("Problem adding user or role from file: ", e);
    } catch (SAXException e) {
      _log.warn("Could not parse user file: ", e);
    } catch (IOException e) {
      _log.warn("Could not parse user file: ", e);
    }
  }

  private Map readMap(Element l) {
    Map map = new HashMap();
    NodeList nodes = l.getChildNodes();
    Set roles = new HashSet();
    for (int i = 0; i < nodes.getLength(); i++) {
      Node item = nodes.item(i);
      if (item instanceof Element) {
        String key = item.getNodeName();
        StringBuffer value = new StringBuffer();
        NodeList vals = item.getChildNodes();
        for (int j = 0; j < vals.getLength(); j++) {
          Node val = vals.item(j);
          if (val instanceof Text) {
            value.append(val.getNodeValue());
          }
        }
        String val = value.toString();
        if (ROLE_ASSIGNMENT.equals(key)) {
          roles.add(val);
        } else {
          map.put(key, val);
        }
      }
    }
    if (roles.size() != 0) {
      map.put(ROLE_ASSIGNMENT, roles);
    }
    return map;
  }

  private void usage() {
    System.out.println("UserFileParser usage:");
    System.out.println("   UserFileParser -d <userDomainName> -f <output file>");
    System.out.println("Reads a user XML file with unencrypted passwords.");
    System.out.println("    The input file name is 'UserFile.xml'");
    System.out.println("Generate a user XML file with digested passwords.");
    System.out.println("    If -f argument is not specified, will create a file named");
    System.out.println("          UserFile-<domain>.xml");
    System.exit(-1);
  }

  private void buildDigestedUserFile(String args[]) {
    // Parse command-line arguments.
    String domain = null;
    String fileName = null;
    for (int i = 0 ; i < args.length ; i++) {
      if (args[i].equals("-d")) {
        if (++i == args.length) {
          usage();
        }
        domain = args[i];
      }
      else if (args[i].equals("-f")) {
        if (++i == args.length) {
          usage();
        }
        fileName = args[i]; 
      }
    }
    if (fileName == null) {
      fileName = "UserFile-" + domain + ".xml";
    }
    
    // The UID is not important. Make a fake one.
    UID uid = UID.toUID("AgentA/1094690973044");
    UserEntries userCache = new UserEntries(uid);
    userCache.setDomain(domain);
    init(userCache);
    
    UserFileParser ufp = new UserFileParser(userCache);
    ufp.readUsers("UserFile.xml");
    OutputStream os = null;
    try {
      os = new FileOutputStream(fileName);
    }
    catch (FileNotFoundException e) {
      usage();
    }
    System.out.println("Generating user XML file: " + fileName
        + " for domain: " + domain);
    ufp.saveUsersAndRoles(os);
  }

  public static void main(String[] args) {
    UserFileParser ufp = new UserFileParser();
    ufp.buildDigestedUserFile(args);
  }
}

/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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

package org.cougaar.core.security.crypto.ldap.admin;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.net.URLEncoder;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.jsp.JspFactory;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import javax.naming.NamingException;
import javax.naming.NamingEnumeration;
import javax.naming.directory.SearchResult;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;

import org.cougaar.core.security.services.crypto.LdapUserService;
import org.cougaar.core.security.certauthority.SecurityServletSupport;
import org.cougaar.core.security.crypto.ldap.KeyRingJNDIRealm;

/**
 * This class is for administration of Users and roles. 
 *
 * You must have an LDAP User database setup. In order to add this servlet
 * to your cougaar configuration, add the following to your agent's ini
 * file in the [ Plugins ] section:
 *
 * <pre>
 * plugin = org.cougaar.core.security.certauthority.CaServletComponent(org.cougaar.core.security.crypto.ldap.admin.UserAdminServlet, /user_admin)
 * </pre>
 *
 * @author George Mount <gmount@nai.com>
 */
public class UserAdminServlet extends HttpServlet {
  
  private static final ModificationItem[] MODS_ARRAY = new ModificationItem[1];

  LdapUserService _userService;
  HttpServlet _admin         = new admin();
  HttpServlet _user          = new user();
  HttpServlet _search_users  = new search_users();
  HttpServlet _user_result   = new user_result();
  HttpServlet _user_edit     = new user_edit();
  HttpServlet _user_new      = new user_new();
  HttpServlet _error         = new error();
  HttpServlet _assign_roles  = new assign_roles();
  HttpServlet _role          = new role();
  HttpServlet _search_roles  = new search_roles();
  HttpServlet _role_new      = new role_new();
  HttpServlet _role_edit     = new role_edit();
  HttpServlet _role_result   = new role_result();

  HttpServlet _allJSPs[] = {
    _admin, _error, _assign_roles,
    _user, _search_users, _user_result, _user_new, _user_edit,
    _role, _search_roles, _role_result, _role_new, _role_edit
  };

  public UserAdminServlet(SecurityServletSupport support) {
    _userService = (LdapUserService) support.getServiceBroker().
      getService(this, LdapUserService.class, null);
    if (JspFactory.getDefaultFactory() == null) {
      JspFactory.setDefaultFactory(new org.apache.jasper.runtime.JspFactoryImpl());
    }
  }

  public void init(ServletConfig config) throws ServletException {
    super.init(config);
    for (int i = 0; i < _allJSPs.length; i++) {
      _allJSPs[i].init(config);
    }
  }

  protected void service(HttpServletRequest req, HttpServletResponse resp) 
    throws ServletException, IOException {
    // Because the pathInfo is broken with cougaar, I have to use a query string parameter
//     String pathInfo = req.getPathInfo();
    String pathInfo = req.getParameter(UserInterface.PAGE);
    try {
//       System.out.println("Servicing request for pathInfo = " + pathInfo);
      /*
      if (pathInfo == null || 
          pathInfo.length() <= _servletPath.length() ||
          !pathInfo.startsWith(_servletPath)) {
        resp.sendRedirect(_servletPath + "/");
        return;
      } 

      pathInfo = pathInfo.substring(_servletPath.length() + 1);
      */

      if (pathInfo == null || pathInfo.length() == 0) {
        _admin.service(req,resp);
      } else if (pathInfo.equals(UserInterface.PAGE_NEW_USER_JSP)) {
        _user_new.service(req,resp);
      } else if (pathInfo.equals(UserInterface.PAGE_NEW_ROLE_JSP)) {
        _role_new.service(req,resp);
      } else if (pathInfo.equals(UserInterface.PAGE_SEARCH_USER)) {
        _user.service(req,resp);
      } else if (pathInfo.equals(UserInterface.PAGE_SEARCH_ROLE)) {
        _role.service(req,resp);
      } else if (pathInfo.equals(UserInterface.PAGE_RESULTS_USER)) {
        search(req,resp,true);
      } else if (pathInfo.equals(UserInterface.PAGE_RESULTS_ROLE)) {
        search(req,resp,false);
      } else if (pathInfo.equals(UserInterface.PAGE_DISPLAY_USER)) {
        gotoUserPage(req,resp,true,false,_user_result);
      } else if (pathInfo.equals(UserInterface.PAGE_DISPLAY_ROLE)) {
        gotoRolePage(req,resp,_role_result);
      } else if (pathInfo.equals(UserInterface.PAGE_EDIT_USER)) {
        editUser(req,resp);
      } else if (pathInfo.equals(UserInterface.PAGE_EDIT_ROLE)) {
        editRole(req,resp);
      } else if (pathInfo.equals(UserInterface.PAGE_NEW_USER)) {
        addUser(req,resp);
      } else if (pathInfo.equals(UserInterface.PAGE_NEW_ROLE)) {
        addRole(req,resp);
      } else if (pathInfo.equals(UserInterface.PAGE_ASSIGN_ROLES)) {
        assignRoles(req,resp);
      } else if (pathInfo.equals(UserInterface.PAGE_BLANK)) {
        blank(req,resp);
      } else if (pathInfo.equals(UserInterface.PAGE_USER_RESULT_ACTION)) {
        String action = req.getParameter(UserInterface.ACTION_BUTTON);
        if (UserInterface.ACTION_BUTTON_COPY.equals(action)) {
          gotoUserPage(req,resp,false,false,_user_new);
        } else if (UserInterface.ACTION_BUTTON_EDIT.equals(action)) {
          gotoUserPage(req,resp,false,false,_user_edit);
        } else if (UserInterface.ACTION_BUTTON_DELETE.equals(action)) {
          deleteUser(req,resp);
        } else if (UserInterface.ACTION_BUTTON_ASSIGN_ROLES.equals(action)) {
          gotoUserPage(req,resp,true,true,_assign_roles);
        }
      } else if (pathInfo.equals(UserInterface.PAGE_ROLE_RESULT_ACTION)) {
        String action = req.getParameter(UserInterface.ACTION_BUTTON);
        if (UserInterface.ACTION_BUTTON_COPY.equals(action)) {
          gotoRolePage(req,resp,_role_new);
        } else if (UserInterface.ACTION_BUTTON_EDIT.equals(action)) {
          gotoRolePage(req,resp,_role_edit);
        } else if (UserInterface.ACTION_BUTTON_DELETE.equals(action)) {
          deleteRole(req,resp);
        }
      }
    } catch (NamingException ex) {
      resp.reset();
      req.setAttribute("exception",ex);
      _error.service(req,resp);
    }
  }
    
  private void blank(HttpServletRequest req, HttpServletResponse resp)
    throws ServletException, IOException, NamingException {
    resp.setContentType("text/html");
    java.io.PrintWriter out = resp.getWriter();
    out.println("<html>");
    if (UserInterface.ACTION_BUTTON_REFRESH.
        equals(req.getParameter(UserInterface.ACTION_BUTTON))) {
      out.println("<head><script language=\"JavaScript\">");
      out.println("top.frames['SearchResultsFrame'].location.reload();");
      out.println("</script></head>");
    }
    out.println("</html>");
  }

  private void search(HttpServletRequest req, HttpServletResponse resp,
                      boolean searchUsers)
    throws ServletException, IOException, NamingException {
    String searchTerm = req.getParameter(UserInterface.SEARCH_TERM);
    String searchOn   = req.getParameter(UserInterface.SEARCH_FIELD);
    String maxResults = req.getParameter(UserInterface.SEARCH_MAX_RESULTS);
    int max;
    
    if (searchTerm == null || searchTerm.length() == 0) searchTerm = "*";
    if (searchOn   == null) {
      if (searchUsers) {
        searchOn = UserInterface.LDAP_USER_UID;
      } else {
        searchOn = UserInterface.LDAP_ROLE_RDN;
      }
    }
    try {
      max = Integer.parseInt(maxResults);
    } catch (Exception e) {
      max = 100;
    }
    NamingEnumeration results = null;
    HttpServlet fwdServlet;
    try {
      if (searchUsers) {
        results = _userService.getUsers(searchTerm, searchOn, max);
        fwdServlet = _search_users;
      } else {
        results = _userService.getRoles(searchTerm, searchOn, max);
        fwdServlet = _search_roles;
      }
      req.setAttribute(UserInterface.SEARCH_RESULTS, results);
      fwdServlet.service(req,resp);
    } finally {
      try {
        if (results != null) results.close();
      } catch (Exception e) {
        // ignore the error.
      }
    }
  }

  private void gotoUserPage(HttpServletRequest req, HttpServletResponse resp,
                            boolean getRoles, boolean getAllRoles, 
                            HttpServlet page)
    throws ServletException, IOException, NamingException {
    String uid = req.getParameter(UserInterface.LDAP_USER_UID);
    NamingEnumeration roles = null;
    NamingEnumeration allRoles = null;
    try {
      if (uid != null) {
        // this is a copied user, put data into the new user page
        req.setAttribute(UserInterface.USER_RESULTS, 
                         _userService.getUser(uid));
        if (getRoles) {
          roles = _userService.getRoles(uid);
          req.setAttribute(UserInterface.ROLE_RESULTS, roles);
        }
        if (getAllRoles) {
          roles = _userService.getRoles(0);
          req.setAttribute(UserInterface.ALL_ROLES, roles);
        }
      }
      page.service(req, resp);
    } finally {
      try {
        if (roles != null) roles.close();
      } catch (Exception e) {
        // ignore closing errors.
      }
    }
  }

  private void gotoRolePage(HttpServletRequest req, HttpServletResponse resp,
                            HttpServlet page)
    throws ServletException, IOException, NamingException {
    String rid = req.getParameter(UserInterface.LDAP_ROLE_RDN);
    if (rid != null) {
      // this is a copied user, put data into the new user page
      req.setAttribute(UserInterface.ROLE_RESULTS, 
                       _userService.getRole(rid));
    }
    page.service(req, resp);
  }

  private void gotoViewUser(HttpServletRequest req, HttpServletResponse resp, String uid) 
    throws ServletException, IOException {
    resp.sendRedirect(req.getRequestURI() + "?" +
                      UserInterface.PAGE + "=" + UserInterface.PAGE_DISPLAY_USER + "&" +
                      URLEncoder.encode(UserInterface.LDAP_USER_UID) +
                      "=" + URLEncoder.encode(uid));
  }

  private void gotoViewRole(HttpServletRequest req, HttpServletResponse resp, String rid) 
    throws ServletException, IOException {
    resp.sendRedirect(req.getRequestURI() + "?" +
                      UserInterface.PAGE + "=" + UserInterface.PAGE_DISPLAY_ROLE + "&" +
                      URLEncoder.encode(UserInterface.LDAP_ROLE_RDN) +
                      "=" + URLEncoder.encode(rid));
  }

  private void gotoViewEmptyPage(HttpServletRequest req, HttpServletResponse resp,
                                 boolean refresh) 
    throws ServletException, IOException {
    String action = "";
    if (refresh) {
      action = UserInterface.ACTION_BUTTON_REFRESH;
    }

    String url = req.getRequestURI() + "?" +
      UserInterface.PAGE + "=" + UserInterface.PAGE_BLANK + "&" +
      UserInterface.ACTION_BUTTON + "=" + action;
    resp.sendRedirect(url);
  }

  private void editUser(HttpServletRequest req, HttpServletResponse resp)
    throws ServletException, IOException, NamingException {

    String uid = req.getParameter(UserInterface.LDAP_USER_UID);
    Attributes orig = _userService.getUser(uid);
    ArrayList mods = new ArrayList();
    for (int i = 0; i < UserInterface.LDAP_USER_FIELDS.length; i++) {
      String field = UserInterface.LDAP_USER_FIELDS[i][0];
      if ( UserInterface.LDAP_USER_UID != field ) {
        String val = req.getParameter(field);
        Attribute attr = orig.get(field);
        ModificationItem mod = null;
        if ( attr != null && (val == null || val.length() == 0) ) {
          // the value has been deleted
          mod = new ModificationItem(DirContext.REMOVE_ATTRIBUTE,
                                     new BasicAttribute(field));
        } else if ( attr == null && (val != null && val.length() != 0) ) {
          // an attribute has been added
          mod = new ModificationItem(DirContext.ADD_ATTRIBUTE,
                                     new BasicAttribute(field,val));
        } else if (attr != null) {
          // the attribute has been changed:
          mod = new ModificationItem(DirContext.REPLACE_ATTRIBUTE,
                                     new BasicAttribute(field,val));
        }
        if (mod != null) {
          mods.add(mod);
        }
      }
    }
    
    // now do the special password field
    String pwd = req.getParameter(UserInterface.LDAP_USER_PASSWORD);
    if (pwd != null) {
      int modType;
      if (orig.get(UserInterface.LDAP_USER_PASSWORD) != null) {
        // modify the password
        modType=DirContext.REPLACE_ATTRIBUTE;
      } else {
        // add the password
        modType=DirContext.ADD_ATTRIBUTE;
      }
      pwd = KeyRingJNDIRealm.encryptPassword(uid, pwd);
      BasicAttribute pwdAttr = new BasicAttribute(UserInterface.LDAP_USER_PASSWORD, 
                                                  pwd.getBytes());
                           
      mods.add(new ModificationItem(modType, pwdAttr));
    }
    _userService.editUser(uid, (ModificationItem[]) mods.toArray(MODS_ARRAY));
    gotoViewUser(req, resp, uid);
  }

  private void editRole(HttpServletRequest req, HttpServletResponse resp)
    throws ServletException, IOException, NamingException {

    String rid = req.getParameter(UserInterface.LDAP_ROLE_RDN);
    Attributes orig = _userService.getRole(rid);
    ArrayList mods = new ArrayList();
    for (int i = 0; i < UserInterface.LDAP_ROLE_FIELDS.length; i++) {
      String field = UserInterface.LDAP_ROLE_FIELDS[i][0];
      if ( UserInterface.LDAP_ROLE_RDN != field ) {
        String val = req.getParameter(field);
        Attribute attr = orig.get(field);
        ModificationItem mod = null;
        if ( attr != null && (val == null || val.length() == 0) ) {
          // the value has been deleted
          mod = new ModificationItem(DirContext.REMOVE_ATTRIBUTE,
                                     new BasicAttribute(field));
        } else if ( attr == null && (val != null && val.length() != 0) ) {
          // an attribute has been added
          mod = new ModificationItem(DirContext.ADD_ATTRIBUTE,
                                     new BasicAttribute(field,val));
        } else if (attr != null) {
          // the attribute has been changed:
          mod = new ModificationItem(DirContext.REPLACE_ATTRIBUTE,
                                     new BasicAttribute(field,val));
        }
        if (mod != null) {
          mods.add(mod);
        }
      }
    }
    
    _userService.editRole(rid, (ModificationItem[]) mods.toArray(MODS_ARRAY));
    gotoViewRole(req, resp,rid);
  }

  private void addUser(HttpServletRequest req, HttpServletResponse resp) 
    throws ServletException, IOException, NamingException {

    String uid = req.getParameter(UserInterface.LDAP_USER_UID);
    BasicAttributes attrs = new BasicAttributes();
    for (int i = 0; i < UserInterface.LDAP_USER_FIELDS.length; i++) {
      String field = UserInterface.LDAP_USER_FIELDS[i][0];
      String val = req.getParameter(field);
      if (val != null && val.length() > 0) {
        attrs.put(field, val);
      }
    }
    
    // now do the password field
    String pwd = req.getParameter(UserInterface.LDAP_USER_PASSWORD);
    if (pwd != null) {
      attrs.put(UserInterface.LDAP_USER_PASSWORD, pwd.getBytes());
    }
    _userService.addUser(uid, attrs);
    gotoViewUser(req, resp, uid);
  }

  private void addRole(HttpServletRequest req, HttpServletResponse resp) 
    throws ServletException, IOException, NamingException {
    String rid = req.getParameter(UserInterface.LDAP_ROLE_RDN);
    BasicAttributes attrs = new BasicAttributes();
//     attrs.put(UserInterface.LDAP_ROLE_USER_RDN, 
//               UserInterface.LDAP_ROLE_DUMMY);
    for (int i = 0; i < UserInterface.LDAP_ROLE_FIELDS.length; i++) {
      String field = UserInterface.LDAP_ROLE_FIELDS[i][0];
      String val = req.getParameter(field);
      if (val != null && val.length() > 0) {
        attrs.put(field, val);
      }
    }
    
    _userService.addRole(rid, attrs);
    gotoViewRole(req, resp,rid);
  }

  private void assignRoles(HttpServletRequest req, HttpServletResponse resp) 
    throws ServletException, IOException, NamingException {

    String uid = req.getParameter(UserInterface.LDAP_USER_UID);
    if (uid == null) {
      gotoViewEmptyPage(req, resp,false);
      return;
    }
    String[] roles = req.getParameterValues(UserInterface.ROLES);

    HashSet roleSet = new HashSet();
    if (roles != null) {
      for (int i = 0; i < roles.length; i++) {
        roleSet.add(roles[i]);
      }
    }
    NamingEnumeration assigned = _userService.getRoles(uid);
    HashSet assignedSet = new HashSet();
    while (assigned.hasMore()) {
      SearchResult role = (SearchResult) assigned.next();
      assignedSet.add(role.getAttributes().get(UserInterface.LDAP_ROLE_RDN).get().toString());
    }
    
    HashSet newRoles = (HashSet) roleSet.clone();
    newRoles.removeAll(assignedSet);
    
    // assign user to new roles
    Iterator iter = newRoles.iterator();
    while (iter.hasNext()) {
      String role = (String) iter.next();
      _userService.assign(uid,role);
    }

    // now remove user from deleted roles
    assignedSet.removeAll(roleSet);
    iter = assignedSet.iterator();
    while (iter.hasNext()) {
      String role = (String) iter.next();
      _userService.unassign(uid,role);
    }
    gotoViewUser(req, resp, uid);
  }

  private void deleteUser(HttpServletRequest req, HttpServletResponse resp) 
    throws ServletException, IOException, NamingException {
    String uid = req.getParameter(UserInterface.LDAP_USER_UID);
    _userService.deleteUser(uid);
    gotoViewEmptyPage(req, resp,true);
  }

  private void deleteRole(HttpServletRequest req, HttpServletResponse resp) 
    throws ServletException, IOException, NamingException {
    String rid = req.getParameter(UserInterface.LDAP_ROLE_RDN);
    _userService.deleteRole(rid);
    gotoViewEmptyPage(req, resp,true);
  }
}


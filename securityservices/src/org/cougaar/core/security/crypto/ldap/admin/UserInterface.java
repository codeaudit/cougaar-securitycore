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

import org.cougaar.core.security.services.acl.UserService;

/**
 * This class is only for keeping the attributes names used to pass
 * values between servlet and jsp.
 */
class UserInterface {
  // get/set Attribute properties
  public static final String SEARCH_RESULTS              = "searchResults";

  public static final String USER_RESULTS                = "userResults";
  public static final String ROLE_RESULTS                = "roleResults";
  public static final String ALL_ROLES                   = "allRoles";

  // field names/values
  public static final String PAGE                        = "page";
  public static final String PAGE_BLANK                  = "blank";
  public static final String PAGE_NEW_USER_JSP           = "newUser.jsp";
  public static final String PAGE_NEW_ROLE_JSP           = "newRole.jsp";
  public static final String PAGE_SEARCH_USER            = "searchUsers";
  public static final String PAGE_SEARCH_ROLE            = "searchRoles";
  public static final String PAGE_RESULTS_USER           = "userResults";
  public static final String PAGE_RESULTS_ROLE           = "roleResults";
  public static final String PAGE_DISPLAY_USER           = "displayUser";
  public static final String PAGE_DISPLAY_ROLE           = "displayRole";
  public static final String PAGE_EDIT_USER              = "editUser";
  public static final String PAGE_EDIT_ROLE              = "editRole";
  public static final String PAGE_NEW_USER               = "newUser";
  public static final String PAGE_NEW_ROLE               = "newRole";
  public static final String PAGE_ASSIGN_ROLES           = "assignRole";
  public static final String PAGE_USER_RESULT_ACTION     = "userAction";
  public static final String PAGE_ROLE_RESULT_ACTION     = "roleAction";

  public static final String SEARCH_TERM                 = "searchTerm";
  public static final String SEARCH_FIELD                = "searchOn";
  public static final String SEARCH_MAX_RESULTS          = "maxResults";

  public static final String ACTION_BUTTON               = "action";
  public static final String ACTION_BUTTON_NEW           = "New";
  public static final String ACTION_BUTTON_COPY          = "Copy";
  public static final String ACTION_BUTTON_DELETE        = "Delete";
  public static final String ACTION_BUTTON_SEARCH        = "Search";
  public static final String ACTION_BUTTON_EDIT          = "Edit";
  public static final String ACTION_BUTTON_SAVE          = "Save";
  public static final String ACTION_BUTTON_CANCEL        = "Cancel";
  public static final String ACTION_BUTTON_ROLE          = "Update Roles";
  public static final String ACTION_BUTTON_ASSIGN_ROLES  = "Assign Roles";
  public static final String ACTION_BUTTON_ADD_USER      = "Add User";
  public static final String ACTION_BUTTON_ADD_ROLE      = "Add Role";
  public static final String ACTION_BUTTON_REFRESH       = "Refresh";

  public static final String ROLES                       = "roles";

  // LDAP attributes:
  public static String LDAP_ROLE_RDN               = "cn";
  public static final String LDAP_ROLE_RDN_TITLE         = "Role Name";
  public static final String LDAP_ROLE_USER_RDN          = "roleOccupant";
  public static final String LDAP_ROLE_USER_RDN_TITLE    = "Users";

  public static String LDAP_USER_UID               = "uid";
  public static final String LDAP_USER_UID_TITLE         = "User ID";
  public static String LDAP_USER_PASSWORD          = "userPassword";
  public static final String LDAP_USER_PASSWORD_TITLE1   = "Password";
  public static final String LDAP_USER_PASSWORD_TITLE2   = "Repeat Password";
  public static String LDAP_USER_ENABLE            = "cougaarAcctEnableTime";
  public static final String LDAP_USER_ENABLE_TITLE      = "Enabled";
  public static String LDAP_USER_AUTH              = "cougaarAuthReq";
  public static final String LDAP_USER_AUTH_TITLE        = "Auth Requirement";
  public static String LDAP_USER_CERTOK            = "certIsSpecial";
  public static final String LDAP_USER_CERTOK_TITLE      = "Cert OK for Disabled Account";
  public static final String LDAP_USER_AUTH_VALS[][]     = {
    {"CERT",     "Certificate Only"},
    {"PASSWORD", "Password Only"},
    {"BOTH",     "Certificate AND Password"},
    {"EITHER",   "Either Certificate or Password"}
  };
  public static final int LDAP_USER_AUTH_DEFAULT_VAL     = 3; // either

  public static String LDAP_SEARCH_FIELDS[][] = {
    { LDAP_USER_UID, LDAP_USER_UID_TITLE },
    { "cn", "Name" },
    { "mail", "Email Address" }
  };

  public static String LDAP_USER_FIELDS[][] = {
    { LDAP_USER_UID,    LDAP_USER_UID_TITLE    },
    { LDAP_USER_ENABLE, LDAP_USER_ENABLE_TITLE },
    { LDAP_USER_CERTOK, LDAP_USER_CERTOK_TITLE },
    { LDAP_USER_AUTH,   LDAP_USER_AUTH_TITLE   },
    { "givenName", "First Name" },
    { "sn", "Last Name" },
    { "cn", "Name" },
    { "mail", "Email Address" }

//     { "title", "Title" },

//     { "street", "Address Line 1" },
//     { "l", "City" },
//     { "st", "State" },
//     { "postalCode", "Zip Code" },

//     {"telephoneNumber", "Work Phone #"},
//     { "homePhone", "Home Phone #" },
//     { "mobile", "Mobile Phone #" },
//     { "pager", "Pager #" },
//     { "facsimileTelephoneNumber", "Fax #" }
  };

  public static String LDAP_ROLE_SEARCH_FIELDS[][] = {
    { LDAP_ROLE_RDN, LDAP_ROLE_RDN_TITLE },
    { "description", "Description" }
  };

  public static String LDAP_ROLE_FIELDS[][] = {
    { LDAP_ROLE_RDN, LDAP_ROLE_RDN_TITLE },
    { "description", "Description" }
//     { LDAP_ROLE_USER_RDN, LDAP_ROLE_USER_RDN_TITLE }
  };

  static void setAttributes(UserService userService) {
    LDAP_ROLE_RDN = userService.getRoleIDAttribute();
    LDAP_USER_UID = userService.getUserIDAttribute();
    LDAP_USER_PASSWORD = userService.getPasswordAttribute();
    LDAP_USER_ENABLE = userService.getEnableTimeAttribute();
    LDAP_USER_AUTH = userService.getAuthFieldsAttribute();
    LDAP_USER_CERTOK = userService.getCertOkAttribute();

    LDAP_USER_FIELDS = new String[][] {
      { LDAP_USER_UID,    LDAP_USER_UID_TITLE    },
      { LDAP_USER_ENABLE, LDAP_USER_ENABLE_TITLE },
      { LDAP_USER_CERTOK, LDAP_USER_CERTOK_TITLE },
      { LDAP_USER_AUTH,   LDAP_USER_AUTH_TITLE   },
      { "givenName", "First Name" },
      { "sn", "Last Name" },
      { "cn", "Name" },
      { "mail", "Email Address" }
    };

    LDAP_ROLE_FIELDS = new String[][] {
      { LDAP_ROLE_RDN, LDAP_ROLE_RDN_TITLE },
      { "description", "Description" }
    };
  }

}

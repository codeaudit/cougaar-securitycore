/*
 * <copyright>
 *  Copyright 1997-2001 Network Associates
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
 */

package org.cougaar.core.security.acl.user;

import org.cougaar.core.util.UniqueObject;
import org.cougaar.core.util.UID;
import java.util.*;
import java.text.*;
import org.cougaar.core.security.services.acl.UserServiceException;

public class UserEntries implements UniqueObject {
  private UID _uid;
  private HashMap _users = new HashMap();
  private HashMap _roles = new HashMap();
  private static final DateFormat DF =
    new SimpleDateFormat("yyyyMMddHHmmss'Z'");
  private static final TimeZone GMT = TimeZone.getTimeZone("GMT");

  public static final String FIELD_UID = "uid";
  public static final String FIELD_PASSWORD = "password";
  public static final String FIELD_ENABLE_TIME = "enableTime";
  public static final String FIELD_CERT_OK = "certOk";
  public static final String FIELD_AUTH = "auth";
  public static final String FIELD_NAME = "cn";
  public static final String FIELD_FNAME = "givenName";
  public static final String FIELD_LNAME = "sn";
  public static final String FIELD_MAIL = "mail";
  public static final String FIELD_RID = "rid";
  public static final String FIELD_DESCRIPTION = "description";
  public static final String FIELD_ROLE_LIST = "roles";

  private static class UserData implements java.io.Serializable {
    //     private String  _userName;
    public Object  password;
    public String  enableTime;
    public boolean certOk;
    public String  auth;
    public String  cn;
    public String  fn;
    public String  sn;
    public String  mail;
    public Set     roles = new HashSet();
  }

  private static class RoleData implements java.io.Serializable {
    public String description;
    public Set    users = new HashSet();
    public Set    subRoles = new HashSet();
  }

  // UniqueObject interface
  public UID getUID() {
    return _uid;
  }

  public void setUID(UID uid) {
    _uid = uid;
  }

  public UserEntries(UID uid) {
    _uid = uid;
  }

  public int getUserCount() { return _users.size(); }
  public int getRoleCount() { return _roles.size(); }
  public String getRoleListAttribute() { return FIELD_ROLE_LIST; }
  public String getPasswordAttribute() { return FIELD_PASSWORD; }
  public String getCertOkAttribute() { return FIELD_CERT_OK; }
  public String getAuthFieldsAttribute() { return FIELD_AUTH; }
  public String getEnableTimeAttribute() { return FIELD_ENABLE_TIME; }
  public String getUserIDAttribute() { return FIELD_UID; }
  public String getRoleIDAttribute() { return FIELD_RID; }

  private UserData getUserData(String uid) throws UserServiceException {
    UserData user = (UserData) _users.get(uid);
    if (user == null) {
      throw new UserServiceException("User does not exist");
    }
    return user;
  }

  public void disableUser(String uid) throws UserServiceException {
    UserData user = getUserData(uid);
    user.enableTime = null;
  }

  private static String toUTCString(long delayMillis) {
    Calendar time = Calendar.getInstance(GMT);
    time.add(time.MINUTE, (int) (delayMillis/60000));
    time.add(time.MILLISECOND, (int) (delayMillis % 60000));
    return DF.format(time.getTime());
  }

  public void disableUser(String uid, long milliseconds) 
    throws UserServiceException {
    UserData user = getUserData(uid);
    user.enableTime = toUTCString(milliseconds);
  }

  public void enableUser(String uid) throws UserServiceException {
    UserData user = getUserData(uid);
    user.enableTime = toUTCString(-60000);
  }

  public Set getUsers(int maxResults) {
    HashSet results = new HashSet();
    synchronized (_users) {
      Iterator iter = _users.keySet().iterator();
      while (iter.hasNext() && 
             (maxResults <= 0 || results.size() < maxResults)) {
        results.add(iter.next());
      }
    }
    return results;
  }

  public Set getUsers(String searchText, String field, int maxResults) 
    throws UserServiceException {
    if (searchText.endsWith("*")) {
      searchText = searchText.substring(0, searchText.length() - 1);
    }
    if (searchText.length() == 0) {
      return getUsers(maxResults);
    }
    Set results = new HashSet();
    synchronized (_users) {
      Iterator iter = _users.entrySet().iterator();
      boolean searchUID = field.equals(FIELD_UID);
      boolean searchName = field.equals(FIELD_NAME);
      boolean searchMail = field.equals(FIELD_MAIL);
      while (iter.hasNext() && 
             (maxResults <= 0 || results.size() < maxResults)) {
        Map.Entry entry = (Map.Entry) iter.next();
        String uid = (String) entry.getKey();
        UserData user = (UserData) entry.getValue();
        if (searchUID) {
          if (uid.indexOf(searchText) != -1) {
            results.add(uid);
          }
        } else if (searchName) {
          if (user.cn.indexOf(searchText) != -1) {
            results.add(uid);
          }
        } else if (searchMail) {
          if (user.mail.indexOf(searchText) != -1) {
            results.add(uid);
          }
        }
      }
    }
    return results;
  }
    
  public Map getUser(String uid) throws UserServiceException {
    UserData entry = (UserData) _users.get(uid);
    if (entry == null) {
      return null;
    }
    Map user = new HashMap();
    user.put(FIELD_UID, uid);
    user.put(FIELD_PASSWORD, entry.password);
    user.put(FIELD_ENABLE_TIME, entry.enableTime);
    user.put(FIELD_CERT_OK, Boolean.valueOf(entry.certOk));
    user.put(FIELD_NAME, entry.cn);
    user.put(FIELD_FNAME, entry.fn);
    user.put(FIELD_LNAME, entry.sn);
    user.put(FIELD_AUTH, entry.auth);
    user.put(FIELD_MAIL, entry.mail);
    synchronized (entry.roles) {
      if (entry.roles.size() != 0) {
        String[] roles = (String[]) 
          entry.roles.toArray(new String[entry.roles.size()]);
        user.put(FIELD_ROLE_LIST, expandRoles(roles));
      }
    }
    return user;
  }

  public void editUser(String uid, Map added, Map edited, Set deleted) 
    throws UserServiceException {
    UserData user = getUserData(uid);
    Iterator iter = null;
    for (int i = 0; i < 2; i++) {
      if (i == 0) {
        if (added != null) {
          iter = added.entrySet().iterator();
        }
      } else if (edited != null) {
        iter = edited.entrySet().iterator();
      }
      while (iter != null && iter.hasNext()) {
        Map.Entry entry = (Map.Entry) iter.next();
        Object key = entry.getKey();
        Object val = entry.getValue();
        if (key.equals(FIELD_PASSWORD)) {
          user.password = val;
        } else if (key.equals(FIELD_ENABLE_TIME)) {
          user.enableTime = (String)val; 
        } else if (key.equals(FIELD_CERT_OK)) {
          if (!(val instanceof Boolean)) {
            val = Boolean.valueOf(val.toString());
          }
          user.certOk = ((Boolean) val).booleanValue();
        } else if (key.equals(FIELD_NAME)) {
          user.cn = (String) val;
        } else if (key.equals(FIELD_FNAME)) {
          user.fn = (String) val;
        } else if (key.equals(FIELD_LNAME)) {
          user.sn = (String) val;
        } else if (key.equals(FIELD_AUTH)) {
          user.auth = (String) val;
        } else if (key.equals(FIELD_MAIL)) {
          user.mail = (String) val;
        }
      }
    }
    if (deleted != null) {
      iter = deleted.iterator();
      while (iter.hasNext()) {
        Object key = iter.next();
        if (key.equals(FIELD_PASSWORD)) {
          user.password = null;
        } else if (key.equals(FIELD_ENABLE_TIME)) {
          user.enableTime = null; 
        } else if (key.equals(FIELD_CERT_OK)) {
          user.certOk = false;
        } else if (key.equals(FIELD_AUTH)) {
          user.auth = null;
        } else if (key.equals(FIELD_NAME)) {
          user.cn = null;
        } else if (key.equals(FIELD_FNAME)) {
          user.fn = null;
        } else if (key.equals(FIELD_LNAME)) {
          user.sn = null;
        } else if (key.equals(FIELD_MAIL)) {
          user.mail = null;
        }
      }
    }
  }
    
  public void addUser(String uid, Map attrs) throws UserServiceException {
    synchronized (_users) {
      if (_users.containsKey(uid)) {
        throw new UserServiceException("User exists");
      }
      UserData user = new UserData();
      _users.put(uid,user);
    }
    if (attrs != null && !attrs.isEmpty()) {
      editUser(uid, attrs, null, null);
    }
  }

  
  /**
   * Removes the given user from the LDAP database
   *
   * @param uid The user's unique identifier
   */
  public void deleteUser(String uid) throws UserServiceException {
    synchronized (_users) {
      UserData user = (UserData) _users.remove(uid);
      if (user == null) {
        throw new UserServiceException("user does not exist");
      }
    }
  }

  /**
   * Returns a <code>Set</code> of role ids that the user belongs to.
   *
   * @param uid The user's unique identifier who is assigned to
   *            the roles you are searching for.
   */
  public Set getRoles(String uid) throws UserServiceException {
    UserData user = getUserData(uid);
    return new HashSet(user.roles);
  }

  /**
   * Returns a <code>Set</code> containing role ids.
   *
   * @param searchText The text to search for in the field
   * @param field The ldap attribute name to search in
   * @param maxResults The maximum number of results to return. Use
   *                   zero (0) to return all results.
   */
  public Set getRoles(String searchText, String field, int maxResults) 
    throws UserServiceException {
    if (searchText.endsWith("*")) {
      searchText = searchText.substring(0, searchText.length() - 1);
    }
    if (searchText.length() == 0) {
      return getRoles(maxResults);
    }
    Set results = new HashSet();
    synchronized (_roles) {
      Iterator iter = _roles.entrySet().iterator();
      boolean searchRID = field.equals(FIELD_RID);
      while (iter.hasNext() && 
             (maxResults <= 0 || results.size() < maxResults)) {
        Map.Entry entry = (Map.Entry) iter.next();
        String rid = (String) entry.getKey();
        RoleData role = (RoleData) entry.getValue();
        if (searchRID) {
          if (rid.indexOf(searchText) != -1) {
            results.add(rid);
          }
        } else {
          if (role.description.indexOf(searchText) != -1) {
            results.add(rid);
          }
        }
      }
    }
    return results;
  }

  /**
   * Returns a <code>Set</code> containing
   * role ids. This returns all
   * roles up to the maxResults.
   *
   * @param maxResults The maximum number of results to return. Use
   *                   zero (0) to return all results.
   */
  public Set getRoles(int maxResults) throws UserServiceException {
    Set results = new HashSet();
    synchronized (_roles) {
      Iterator iter = _roles.keySet().iterator();
      while (iter.hasNext() && 
             (maxResults <= 0 || results.size() < maxResults)) {
        results.add(iter.next());
      }
    }
    return results;
  }

  private RoleData getRoleData(String rid) throws UserServiceException {
    RoleData role = (RoleData) _roles.get(rid);
    if (role == null) {
      throw new UserServiceException("Role does not exist");
    }
    return role;
  }

  /**
   * Returns a role's attributes.
   *
   * @param rid The role's unique identifier
   */
  public Map getRole(String rid) throws UserServiceException {
    RoleData data = getRoleData(rid);
    if (data == null) {
      return null;
    }
    Map role = new HashMap();
    role.put(FIELD_RID, rid);
    role.put(FIELD_DESCRIPTION, data.description);
    role.put(FIELD_ROLE_LIST, new HashSet(data.subRoles));
    return role;
  }

  /**
   * Assigns a user to a role
   *
   * @param uid The user's unique identifier
   * @param rid The role's unique identifier
   */
  public void assign(String uid, String rid) throws UserServiceException {
    RoleData role = getRoleData(rid);
    UserData user = getUserData(uid);
    synchronized(role.users) {
      synchronized(user.roles) {
        role.users.add(uid);
        user.roles.add(rid);
      }
    }
  }

  /**
   * Unassigns a user from a role
   *
   * @param uid The user's unique identifier
   * @param rid The role's unique identifier
   */
  public void unassign(String uid, String rid) throws UserServiceException {
    RoleData role = getRoleData(rid);
    UserData user = getUserData(uid);
    synchronized(role.users) {
      synchronized(user.roles) {
        role.users.remove(uid);
        user.roles.remove(rid);
      }
    }
  }

  /**
   * Creates a role with the given unique identifier and all other attributes
   * empty.
   *
   * @param rid The role's unique identifier
   */
  public void addRole(String rid) throws UserServiceException {
    synchronized(_roles) {
      if (_roles.containsKey(rid)) { 
        throw new UserServiceException("Role already exists");
      }
      _roles.put(rid, new RoleData());
    }
  }

  /**
   * Creates a role with the given unique identifier and attributes as given
   * by attrs.
   *
   * @param rid The role's unique identifier
   * @param attrs The role's attributes
   */
  public void addRole(String rid, Map attrs) throws UserServiceException {
    addRole(rid);
    if (attrs != null && attrs.size() != 0) {
      editRole(rid, attrs, null, null);
    }
  }

  /**
   * Modifies a role's LDAP attributes.
   *
   * @param rid The role's unique identifier
   * @param added Attributes to be added
   * @param edited Attributes to be modified
   * @param deleted The attributes whose value should be removed
   */
  public void editRole(String rid, Map added, Map edited, Set deleted) 
    throws UserServiceException {
    RoleData role = getRoleData(rid);
    Iterator iter = null;
    for (int i = 0; i < 2; i++) {
      if (i == 0) {
        if (added != null) {
          iter = added.entrySet().iterator();
        }
      } else if (edited != null) {
        iter = edited.entrySet().iterator();
      }
      while (iter != null && iter.hasNext()) {
        Map.Entry entry = (Map.Entry) iter.next();
        Object key = entry.getKey();
        Object val = entry.getValue();
        if (key.equals(FIELD_DESCRIPTION)) {
          role.description = (String)val;
        } 
      }
    }
    if (deleted != null) {
      iter = deleted.iterator();
      while (iter.hasNext()) {
        Object key = iter.next();
        if (key.equals(FIELD_DESCRIPTION)) {
          role.description = null;
        }
      }
    }
  }

  /**
   * Creates a hierarchical relationship between two roles. 
   *
   * @param container The Container role.
   * @param containee The role to be contained.
   * @throws UserServiceException If the subordinate contains the superior,
   * directly or indirectly or if there is an error communicating with the
   * database.
   */
  public void addRoleToRole(String container, String containee)
    throws UserServiceException {
    Set contained = new HashSet();
    expandRoles(containee, contained);
    if (contained.contains(container)) {
      throw new UserServiceException("Trying to create circular role heirarchy");
    }

    RoleData role = getRoleData(container);
    synchronized(role.subRoles) {
      if (role.subRoles.contains(containee)) {
        throw new UserServiceException("Role already exists");
      }
      role.subRoles.add(containee);
    }
  }

  /**
   * Removes a hierarchical relationship between two roles. 
   *
   * @param container The container role.
   * @param containee The contained role.
   * @throws UserServiceException If there is an error communicating with the
   * database.
   */
  public void removeRoleFromRole(String container, String containee)
    throws UserServiceException {
    RoleData role = getRoleData(container);
    synchronized(role.subRoles) {
      if (role.subRoles.remove(containee)) {
        throw new UserServiceException("Role is not contained");
      }
    }
  }

  private void expandRoles(String rid, Set roles) {
    RoleData role = (RoleData) _roles.get(rid);
    Set newRoles = new HashSet(role.subRoles);
    newRoles.removeAll(roles);
    roles.addAll(newRoles);
    Iterator iter = newRoles.iterator();
    while (iter.hasNext()) {
      expandRoles((String) iter.next(), roles);
    }
  }

  /**
   * Expands the role hierarchy for the given set of role ids
   *
   * @param rids array of role ids to expand
   */
  public Set expandRoles(String[] rids) throws UserServiceException {
    Set roles = new HashSet();
    for (int i = 0; i < rids.length; i++) {
      roles.add(rids[i]);
      expandRoles(rids[i], roles);
    }
    return roles;
  }

  /**
   * Returns a list of roles that this role contains.
   *
   * @param rid The container role to check
   * @throws UserServiceException If there is an error communicating with the
   * database.
   */
  public Set getContainedRoles(String rid) throws UserServiceException {
    RoleData role = getRoleData(rid);
    return role.subRoles;
  }

  /**
   * Returns a list of users that have this role.
   *
   * @param rid The role to check
   * @throws UserServiceException If there is an error communicating with the
   * database.
   */
  public Set getUsersInRole(String rid) throws UserServiceException {
    RoleData role = getRoleData(rid);
    return role.users;
  }

  /**
   * Deletes a role from the LDAP database.
   *
   * @param rid The role's unique identifier
   */
  public void deleteRole(String rid) throws UserServiceException {
    synchronized (_roles) {
      if (_roles.remove(rid) == null) {
        throw new UserServiceException("Role does not exist");
      }
    }
  }
}

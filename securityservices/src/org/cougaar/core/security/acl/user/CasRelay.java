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

import java.io.Serializable;
import java.util.*;

import org.cougaar.core.relay.*;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.util.UID;
import org.cougaar.core.util.UniqueObject;
import org.cougaar.core.security.util.RelayBase;

public class CasRelay extends RelayBase {
  public CasRelay(UID uid, MessageAddress source, Object content) {
    super(uid, source, content);
  }

  public CasRelay(UID uid, MessageAddress source, MessageAddress target) {
    super(uid, source, target);
  }

  public CasRelay(UID uid, MessageAddress source, Set targets) {
    super(uid, source, targets);
  }

  public void disableUser(String uid) {
    _content = new CasRequest(LOCK_USER, uid);
  }
  
  public void disableUser(String uid, long milliseconds) {
    _content = new CasRequest(LOCK_USER_4_TIME, 
                              new Object[] {uid, new Long(milliseconds)});
  }

  public void enableUser(String uid) {
    _content = new CasRequest(UNLOCK_USER, uid);
  }

  public void getUsers(String searchText, String field, int maxResults) {
    _content = new CasRequest(SEARCH_USERS, new Object[] {
      searchText, field, new Integer(maxResults) });
  }

  public void getUser(String uid) {
    _content = new CasRequest(GET_USER, uid);
  }

  public void editUser(String uid, Map added, Map edited, Set deleted) {
    _content = new CasRequest(EDIT_USER, new Object[] {
      uid, added, edited, deleted
    });
  }

  public void addUser(String uid, Map attrs) {
    _content = new CasRequest(ADD_USER, new Object[] {
      uid, attrs
    });
  }

  public void deleteUser(String uid) {
    _content = new CasRequest(DEL_USER, uid);
  }

  public void getRoles(String uid) {
    _content = new CasRequest(GET_USER_ROLES, uid);
  }

  public void getRoles(String searchText, String field,
                       int maxResults) {
    _content = new CasRequest(SEARCH_ROLES, new Object[] {
      searchText, field, new Integer(maxResults)
    });
  }

  public void getRoles(int maxResults) {
    _content = new CasRequest(GET_ROLES, new Integer(maxResults));
  }

  public void getRole(String rid) {
    _content = new CasRequest(GET_ROLE, rid);
  }

  public void assign(String uid, String rid) {
    _content = new CasRequest(ROLE2USER, new Object[] {
      uid, rid
    });
  }

  public void unassign(String uid, String rid) {
    _content = new CasRequest(UNASSIGN_USER, new Object[] {
      uid, rid
    });
  }

  public void addRole(String rid) {
    _content = new CasRequest(ADD_ROLE, new Object[] {
      rid, null
    });
  }

  public void addRole(String rid, Map attrs) {
    _content = new CasRequest(ADD_ROLE, new Object[] {
      rid, attrs
    });
  }

  public void editRole(String rid, Map added, Map edited, Set deleted) {
    _content = new CasRequest(EDIT_ROLE, new Object[] {
      rid, added, edited, deleted
    });
  }

  public void addRoleToRole(String container, String containee){
    _content = new CasRequest(ROLE2ROLE, new Object[] {
      container, containee
    });
  }

  public void removeRoleFromRole(String container, String containee) {
    _content = new CasRequest(UNASSIGN_ROLE, new Object[] {
      container, containee
    });
  }

  public void expandRoles(String[] rids) {
    _content = new CasRequest(EXPAND_ROLES, rids);
  }

  public void getContainedRoles(String rid) {
    _content = new CasRequest(GET_SUB_ROLES, rid);
  }

  public void getUsersInRole(String rid) {
    _content = new CasRequest(GET_ROLE_USERS, rid);
  }

  public void deleteRole(String rid) {
    _content = new CasRequest(DEL_ROLE, rid);
  }

  public static final int LOCK_USER        = 1;
  public static final int LOCK_USER_4_TIME = 2;
  public static final int UNLOCK_USER      = 3;
  public static final int SEARCH_USERS     = 4;
  public static final int GET_USER         = 5;
  public static final int EDIT_USER        = 6;
  public static final int ADD_USER         = 7;
  public static final int DEL_USER         = 8;
  public static final int GET_USER_ROLES   = 9;
  public static final int SEARCH_ROLES     = 10;
  public static final int GET_ROLES        = 11;
  public static final int GET_ROLE         = 12;
  public static final int ROLE2USER        = 13;
  public static final int UNASSIGN_USER    = 14;
  public static final int ADD_ROLE         = 15;
  public static final int EDIT_ROLE        = 16;
  public static final int ROLE2ROLE        = 17;
  public static final int UNASSIGN_ROLE    = 18;
  public static final int EXPAND_ROLES     = 19;
  public static final int GET_SUB_ROLES    = 20;
  public static final int GET_ROLE_USERS   = 21;
  public static final int DEL_ROLE         = 22;

  public static class CasRequest implements java.io.Serializable {
    private int _type;
    private Object _args;

    public CasRequest(int type, Object args) {
      _type = type;
      _args = args;
    }

    public int getType() { return _type; }
    public Object getArgs() { return _args; }
    public String toString() {
      if (_args instanceof Object[]) {
        StringBuffer buf = new StringBuffer("<CasRequest type=\"");
        buf.append(_type).append("\" args=\"[");
        Object[] arr = (Object[]) _args;
        for (int i = 0; i < arr.length; i++) {
          if (i != 0) {
            buf.append(", ");
          }
          buf.append(arr[i]);
        }
        buf.append("\">");
        return buf.toString();
      }
      return "<CasRequest type=\"" + _type + "\" args=\"" +
        _args + "\">";
    }
  }

  public static class CasResponse implements java.io.Serializable {
    private boolean _ok;
    private Object  _resp;
    
    public CasResponse(Object response) {
      _resp = response;
      _ok = !(response instanceof Throwable);
    }
    
    public Object getResponse() { return _resp; }
    public boolean isOk() { return _ok; }
    public String toString() {
      return "<CasResponse ok=\"" + _ok + "\" response=\"" +
        _resp + "\">";
    }
  }
}

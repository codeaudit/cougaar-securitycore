/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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
 *
 */

package org.cougaar.core.security.auth;

import java.security.Permission;
import java.util.StringTokenizer;

/**
 * A Java security manager permission to add, delete, change, or 
 * query the black board service.
 *
 * For example, the following permission only allows components in myfile.jar 
 * to query for only java.lang objects from the blackboard.
 *
 * grant codeBase "file:${org.cougaar.install.path}${/}sys${/}myfile.jar" signedBy "privileged" {
 *  ....
 *  permission org.cougaar.core.security.auth.BlackboardPermission "java.lang.*", "query";
 *  ....
 * };
 *
 */
public final class BlackboardPermission extends ServicePermission {
  
  // add action
  private final static int ADD    = 0x1;
  // change action
  private final static int CHANGE = 0x2;
  // remove action
  private final static int REMOVE = 0x4;
  // query action 
  private final static int QUERY  = 0x8;   
  // all actions (add,change,remove,query)
  private final static int ALL    = ADD|CHANGE|REMOVE|QUERY;
  // no actions
  private final static int NONE   = 0x0;

  // the actions mask
  private transient int _mask = NONE;
  // if there is a wildcard in _name
  private transient boolean _wildcard;
  // object name or package
  private String _name;
  // string representation of the actions
  private String _actions;
  
  /**
   * A blackboard permission to add, change, remove, and/or query for a particular 
   * object or package.
   *
   * @param name the class or package name (for example java.lang.String or java.lang.*)
   * @param actions add, change, remove, and/or query (* for all actions)
   */
  public BlackboardPermission(String name, String actions) {
    super(name);
    if(name == null) {
	    throw new NullPointerException("name can't be null");
    }
	  else if(name.equals("")) {
	    throw new IllegalArgumentException("name can't be empty");
	  }
    else if(actions == null) {
      throw new NullPointerException("actions can't be null");
    }
    else if(actions.equals("")) {
      throw new IllegalArgumentException("actions can't be empty");
    }
    init(name);
    processActions(actions);
  }
  public boolean equals(Object obj){
    if(obj == this) {
      return true; 
    }
    if(obj == null || !(obj instanceof BlackboardPermission)) {
      return false; 
    }
    BlackboardPermission bbp = (BlackboardPermission)obj;
    return (_mask == bbp._mask &&
           _name.equals(bbp._name));
  } 
  public String getActions()  {
    // should we return the permission representation of '*'????
    return _actions;
  }
  public int hashCode()  {
    return _name.hashCode();
  }
  public boolean implies(Permission p) {
    if(!(p instanceof BlackboardPermission)) {
      return false;
    }
    BlackboardPermission bbp = (BlackboardPermission)p;
    
    return ((this._mask & bbp._mask) == bbp._mask &&
            impliesIgnoreMask(bbp));
  }
  // initializes the class or package name
  private void init(String name) {
	  if(name.endsWith(".*") || name.equals("*")) {
	    _wildcard = true;
	    if(name.length() == 1) {
		    _name = "";
	    } 
	    else {
	      // get everything up to the '*'
		    _name = name.substring(0, name.length() - 1);
	    }
	  } 
	  else {
	    // a class name
	    _name = name;
	  }
  }
  // process the actions string from the permission
  private void processActions(String actions) {
    // should we do something with this?
    _actions = actions;

    if(actions.equals("*")) {
      _mask = ALL;
    }
    else {
      StringTokenizer st = new StringTokenizer(actions, ",");
      while(st.hasMoreTokens()) {
        String perm = st.nextToken(); 
        if(perm.equalsIgnoreCase("add")) {
          _mask |= ADD;
        }
        else if(perm.equalsIgnoreCase("change")) {
          _mask |= CHANGE;
        }
        else if(perm.equalsIgnoreCase("remove")) {
          _mask |= REMOVE;
        }
        else if(perm.equalsIgnoreCase("query")) {
          _mask |= QUERY;
        }
        else {
    		  throw new IllegalArgumentException("invalid action");
        }
      }
    }
  }
  // determine if the class or package name matches
  private boolean impliesIgnoreMask(BlackboardPermission p) {
	  if(_wildcard) {
	    if(p._wildcard) {
		  // one wildcard can imply another
		    return p._name.startsWith(_name);
	    }
	    else {
		    // make sure p._name is longer so a.b.* doesn't imply a.b
		    return (p._name.length() > _name.length()) &&
		        p._name.startsWith(_name);
		  }
	  } 
	  else {
	    if(p._wildcard) {
		    // a non-wildcard can't imply a wildcard
		    return false;
	    }
	    else {
	      // must be a class name
		    return _name.equals(p._name);
	    }
	  } 
  }
}

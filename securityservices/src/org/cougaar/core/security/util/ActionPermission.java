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

package org.cougaar.core.security.util;

import java.security.Permission;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.StringTokenizer;

public class ActionPermission extends java.security.Permission {
  private static long NONE = 0x0;
  private static final String[] EMPTY_STRING_ARRAY = {};

  private String        _name;
  private boolean      _wildName;
  private boolean      _nameIsOther;
  private long         _mask = NONE;
  private String       _actionStr;

  public ActionPermission(String name) {
    super(name);
    if(name == null) {
      throw new NullPointerException("name can't be null");
    } else if(name.equals("")) {
      throw new IllegalArgumentException("name can't be empty");
    }
    parseName(name);
  }

  public ActionPermission(String name, String actions) {
    super(name);
    if(name == null) {
      throw new NullPointerException("name can't be null");
    } else if(name.equals("")) {
      throw new IllegalArgumentException("name can't be empty");
    } else if(actions == null) {
      throw new NullPointerException("actions can't be null");
    } else if(actions.equals("")) {
      throw new IllegalArgumentException("actions can't be empty");
    }

    parseName(name);
    parseActions(actions);
  }

  /**
   * If you want to support actions, you must override this method
   * to return a sorted array containing a complete set of action names.
   */
  protected String[] getAvailableActions() {
    return EMPTY_STRING_ARRAY;
  }

  public boolean implies(Permission permission) {
    return (this.getClass().isInstance(permission) &&
            nameMatches(permission.getName()) &&
            (_mask & ((ActionPermission)permission)._mask) == _mask);
  }

  public String getActions() {
    return _actionStr;
  }

  public String [] getActionList() {
    return getActions(getActions());
  }

  protected Set nameableObjects()
  {
    HashSet ret = null;
    return ret;
  }

  protected boolean nameMatches(String name) {
    if (name == null) {
      return false;
    } else if (_nameIsOther) {
      Set nameable = nameableObjects();
      if (nameable == null) {
        throw new RuntimeException
          ("Other objects not supported by this permission type");
      }
      return ! nameable.contains(name);
    } else if (_wildName) {
      return name.startsWith(_name);
    } else {
      return name.equals(_name);
    }
  }

  public int hashCode() {
    return _name.hashCode() ^ ((int)_mask);
  }

  public boolean equals(Object obj) {
    if (this.getClass().isInstance(obj)) {
      ActionPermission p = (ActionPermission) obj;
      return
        (_name.equals(p._name) &&
         _actionStr.equals(p._actionStr) &&
         _wildName == p._wildName &&
         _nameIsOther == p._nameIsOther &&
         _mask == p._mask);
    }
    return false;
  }

  protected void parseName(String name) {
    _name = name;
    if (name.equals("%Other%")) {
      _nameIsOther = true;
      _wildName    = false;
    } else if (name.endsWith(".*") || name.equals("*")) {
      _nameIsOther = false;
      _wildName = true;
      // get everything up to the '*'
      _name = _name.substring(0, name.length() - 1);
    } else {
      // a class name
      _nameIsOther = false;
      _wildName = false;
    }
  }

  protected void parseActions(String actions) {
    String actionList[] = getActions(actions);
    Arrays.sort(actionList);
    StringBuffer buf = new StringBuffer();
    for (int i = 0; i < actionList.length; i++) {
      if (i != 0) {
        buf.append(',');
      }
      buf.append(actionList[i]);
    }
    _actionStr = buf.toString();
    // now turn the actionList into a mask:
    String allActions[] = getAvailableActions();
    if (allActions.length > 64) {
      throw new IllegalStateException("You may only have up to 64 different action types with ActionPermission");
    }
    int j = 0;
    for (int i = 0; i < actionList.length; i++) {
      int comp;
      do {
        comp = allActions[j].compareTo(actionList[i]);
        if (comp > 0) {
          throw new IllegalArgumentException("Action " + actionList[i] +
                                             " is not legal");
        }
        j++;
      } while (comp < 0);
      // found it at (j-1)
      _mask |= 1 << (j -1);
    }
  }

  protected String[] getActions(String actions) {
    if (actions == null) {
      return EMPTY_STRING_ARRAY;
    }
    actions = actions.trim(); // get rid of whitespace

    StringTokenizer tok = new StringTokenizer(actions, ",");
    String[] actionList = new String[tok.countTokens()];
    int i = 0;
    while (tok.hasMoreTokens()) {
      String token = tok.nextToken().trim();
      if (token.equals("*")) {
        return getAvailableActions(); // all actions
      }
      actionList[i] = token;
      i++;
    }
    return actionList;
  }
}


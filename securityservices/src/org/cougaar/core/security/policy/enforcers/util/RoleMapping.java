/*
 * <copyright>
 *  Copyright 2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency *  (DARPA).
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

package org.cougaar.core.security.policy.enforcers.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;
import java.util.Set;
import java.util.HashSet;
import java.util.Map;
import java.util.HashMap;

import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.util.ConfigFinder;



/**
 * The purpose of this class is to facilitate the mapping between DAML
 * concepts and the UltraLog concepts.  For now I am using
 * configuration files but some of this will change later...
 */
public class RoleMapping extends StringPairMapping {

  private Map  _componentMap;
  private Map  _agentMap;
  private Map  _uriMap;

  public RoleMapping(ServiceBroker sb)
  {
    super(sb);
    if (_log.isDebugEnabled()) {
      _log.debug("Initializing Role Mapper");
    }
    initializeComponent();
    initializeAgent();
    initializeUri();
  }


  private void initializeComponent() {
    try {
      _log.debug("loading component/role mappings...");
      _componentMap = loadMap("RoleComponentMap");
    } catch (IOException e) {
      _log.error("IOException reading coponent -> role configuration file", e);
    }
  }

  private void initializeAgent() {
    try {
      _log.debug("loading agent/role mappings...");
      _agentMap = loadMap("RoleAgentMap");
    } catch (IOException e) {
      _log.error("IOException reading agent -> role configuration file", e);
    }
  }

  private void initializeUri() {
    try {
      _log.debug("loading uri/role mappings...");
      _uriMap = loadMap("RoleUriMap");
    } catch (IOException e) {
      _log.error("IOException reading uri -> role configuration file", e);
    }
  }

  public Set getRolesForComponent(String className) {
    int index = className.length();
    int jndex;
    HashSet roles = new HashSet();
    while (index != -1) {
      className = className.substring(0, index);
      Set s = (Set) _componentMap.get(className);
      if (s != null) {
        roles.addAll(s);
      }
      index = className.lastIndexOf('.');
      jndex = className.lastIndexOf('$');
      if (jndex > index) {
        index = jndex;
      }
    }
    return roles;
  }

  public Set getRolesForAgent(String agent) {
    Set roles = (Set) _agentMap.get(agent);
    if (roles == null) {
      return new HashSet();
    }
    return new HashSet(roles); // need to clone so they can't change it?
  }

  public Set getRolesForUri(String uri) {
    int index;
    boolean first = true;
    String agent = null;
    if (uri.startsWith("/$")) {
      index = uri.indexOf('/',2);
      if (index == -1) {
        agent = uri;
        uri = "/";
      } else {
        agent = uri.substring(0, index);
        uri = uri.substring(index+1);
      }
    }
    index = uri.length();
    while (index != -1) {
      if (first) {
        first = false;
      } else {
        uri = uri.substring(0, index + 1) + "*";
      }
      Set s;
      if (agent != null) {
        s = (Set) _uriMap.get(agent + uri);
        if (s != null) {
          return new HashSet(s); // copy the set
        }
        s = (Set) _uriMap.get("/$*" + uri);
      } else {
        s = (Set) _uriMap.get(uri);
      }
      if (s != null) {
        return new HashSet(s); // copy the set
      }
      index = uri.lastIndexOf('/');
    }
    return new HashSet(); // no roles;
  }
}

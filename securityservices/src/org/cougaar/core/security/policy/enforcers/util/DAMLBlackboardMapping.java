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

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.policy.enforcers.ontology.jena.EntityInstancesConcepts;
import org.cougaar.core.service.LoggingService;

import java.io.IOException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;


/**
 * The purpose of this class is to facilitate the mapping between DAML
 * concepts and the UltraLog concepts.  For now I am using
 * configuration files but some of this will change later...
 */
public class DAMLBlackboardMapping  {

  public static final String otherBlackboardObjectDAML = 
    EntityInstancesConcepts.EntityInstancesDamlURL + "otherBlackboardObjects";
  private boolean            _initialized = false;
  private List                _objectMap;
  private ServiceBroker       _sb;
  private LoggingService      _log; 

  public DAMLBlackboardMapping(ServiceBroker sb)
  {
    _sb = sb;
    _log = (LoggingService) sb.getService(this, LoggingService.class, null);
    if (_log.isDebugEnabled()) {
      _log.debug("Initializing DAML Blackboard Mapper");
    }
  }


  public void initialize()
  {
    try {
      _log.debug("loading daml blackboard object mappings...");
      _objectMap = new StringPairMapping(_sb, "DamlBlackboardObjectMap")
                                                       .buildPairList();
    } catch (IOException e) {
      _log.error("IO Exception reading DAML <-> " + 
                 "blackboard configuration file", e);
    }
  }

  public String classToDAMLName(String classname)
  {
    try {
      _log.debug("Converting " + classname + " to KAoS name");
      for (Iterator objectIt = _objectMap.iterator();
           objectIt.hasNext();) {
        StringPair pair = (StringPair) objectIt.next();
        if (match(pair._first, classname)) {
          return pair._second;
        }
      }
    } catch (Exception e) {
      _log.warn("This is probably not good", e);
      return null;
    }
    return otherBlackboardObjectDAML;
  }


  public Set damlToClassNames(String damlname)
  {
    HashSet objectNamesUL = new HashSet();
    for (Iterator objectIt = _objectMap.iterator();
         objectIt.hasNext();) {
      StringPair pair = (StringPair) objectIt.next();
      if (pair._second.equals(damlname)) {
        objectNamesUL.add(pair._first);
      }
    }
    return objectNamesUL;
  }

  public Set namedObjects()
  {
    HashSet namedClasses = new HashSet();
    for (Iterator objectIt = _objectMap.iterator();
         objectIt.hasNext();) {
      StringPair pair = (StringPair) objectIt.next();
      namedClasses.add(pair._first);
    }
    return namedClasses;
  }

  public Set allDAMLObjectNames()
  {
    HashSet namedClasses = new HashSet();
    for (Iterator objectIt = _objectMap.iterator();
         objectIt.hasNext();) {
      StringPair pair = (StringPair) objectIt.next();
      namedClasses.add(pair._second);
    }
    namedClasses.add(otherBlackboardObjectDAML);
    return namedClasses;
  }

  protected static boolean match(String model, String classname)
  {
    if (model.endsWith("*")) {
      return classname.startsWith(model.substring(0,model.length() - 1));
    } else {
      return model.equals(classname);
    }
  }
}

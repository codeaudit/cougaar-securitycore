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
import java.io.InputStream;
import java.io.InputStreamReader;
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
public class StringPairMapping {

  protected LoggingService _log;
  private ConfigFinder _cf;

  public StringPairMapping(ServiceBroker sb)
  {
    _log = (LoggingService)
      sb.getService(this,
                    LoggingService.class, 
                    null);
    if (_log.isDebugEnabled()) {
      _log.debug("Initializing String Pair Mapper");
    }
    _cf = ConfigFinder.getInstance();
  }

  /**
   * This method reads a mapping from a file.  
   *
   * We assume that the mapping is functional.
   */

  public List loadPairs(String filename)
    throws IOException
  {
    _log.debug(".loadPairs Initilizing String Pair mapping using " + filename);

    List mapping = new Vector();
    File policyFile = null;
    String line;

    InputStream mappingIs = _cf.open(filename);

    if (mappingIs == null) {
      if (_log.isErrorEnabled()) {
         _log.error("Cannot find String Pair mapping file:" + filename);
      }
      return new Vector();
    }
    BufferedReader damlReader 
      = new BufferedReader(new InputStreamReader(mappingIs));
    while ((line = damlReader.readLine()) != null) {
      if (line.startsWith("#")) { continue; }

      int spacePt;
      if ((spacePt = line.indexOf(' ')) == -1) { continue; }
      String mappingIn = line.substring(0,spacePt);
      String mappingOut = line.substring(spacePt+1);

      _log.debug(".loadPairs: mapping item " + mappingIn +
                " to item " + mappingOut);

      if (mappingOut == null)
        continue;

      mapping.add(new StringPair(mappingIn, mappingOut));
    }
    damlReader.close();
    _log.debug(".loadPairs: Finished Reading daml policies file " 
              + filename);
    return mapping;
  }

  public Map loadMap(String filename) throws IOException {
    Map m = new HashMap();
    List l = loadPairs(filename);
    Iterator iter = l.iterator();
    while (iter.hasNext()) {
      StringPair p = (StringPair) iter.next();
      Set s = (Set) m.get(p._first);
      if (s == null) {
        s = new HashSet();
        m.put(p._first, s);
      }
      s.add(p._second);
    }
    return m;
  }

  public static class StringPair
  {
    public String _first;
    public String _second;

    public StringPair(String first, String second)
    {
      _first  = first;
      _second = second;
    }
  }

}

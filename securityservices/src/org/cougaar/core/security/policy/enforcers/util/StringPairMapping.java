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


package org.cougaar.core.security.policy.enforcers.util;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.LoggingService;
import org.cougaar.util.ConfigFinder;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;



/**
 * The purpose of this class is to facilitate the mapping between DAML
 * concepts and the UltraLog concepts.  For now I am using
 * configuration files but some of this will change later...
 */
public class StringPairMapping {

  protected LoggingService _log;
  private   ConfigFinder   _cf;
  protected List           _mapping;
  private   String         _filename;

  public StringPairMapping(ServiceBroker sb, String filename)
    throws IOException
  {
    _log = (LoggingService) sb.getService(this, LoggingService.class, null);
    if (_log.isDebugEnabled()) {
      _log.debug("Initializing String Pair Mapper");
    }
    _cf = ConfigFinder.getInstance();
    _mapping = loadPairs(filename);
  }

  /**
   * This method reads a mapping from a file.  
   */

  private List loadPairs(String filename)
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

      mapping.add(new StringPair(mappingIn, mappingOut.trim()));
    }
    damlReader.close();
    _log.debug(".loadPairs: Finished Reading daml policies file " 
              + filename);
    return mapping;
  }

  public Map buildMap() throws IOException {
    Map m = new HashMap();
    Iterator iter = _mapping.iterator();
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

  public Map buildFunctionalMap()
    throws IOException {
    Map m = new HashMap();
    Iterator iter = _mapping.iterator();
    if (_log.isDebugEnabled()) {
      _log.debug("getting mappings for filename " + _filename);
    }
    while (iter.hasNext()) {
      StringPair p = (StringPair) iter.next();
      String s = (String) m.get(p._first);
      if (_log.isDebugEnabled()) {
        _log.debug(p._first + " --> " + p._second);
      }
      if (s != null) {
        throw new IOException("Configuration file " + _filename +
                              " is not functional.");
      }
      m.put(p._first, p._second);
    }
    return m;
  }

  public List buildPairList()
  {
    return _mapping;
  }
}

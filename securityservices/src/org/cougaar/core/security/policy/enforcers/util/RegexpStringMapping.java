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

import java.io.IOException;

import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import org.apache.regexp.RE;
import org.apache.regexp.RESyntaxException;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.LoggingService;

public class RegexpStringMapping extends StringPairMapping
{
  List _regexpMapping;

  public RegexpStringMapping(ServiceBroker sb, String fileName)
    throws IOException, RESyntaxException
  {
    super(sb);

    _log = (LoggingService) sb.getService(this, LoggingService.class, null);

    _regexpMapping = new Vector();
    List stringPairs = loadPairs(fileName);
    for (Iterator stringPairsIt = stringPairs.iterator(); 
         stringPairsIt.hasNext();) {
      StringPair stringPair = (StringPair) stringPairsIt.next();
      _regexpMapping.add(new RegexpPair(stringPair._first, 
                                        stringPair._second));
    }
  }

  public String functionalGet(String key)
  {
    if (_log.isDebugEnabled()) {
      _log.debug("Attempting to map key " + key);
    }
    for (Iterator mappingIt = _regexpMapping.iterator();
         mappingIt.hasNext();) {
      RegexpPair rp = (RegexpPair) mappingIt.next();
      if (rp._first.match(key)) {
        if (_log.isDebugEnabled()) {
          _log.debug("" + key + " maps to " + rp._second);
        }
        return rp._second;
      }
    }
    if (_log.isDebugEnabled()) {
      _log.debug("No match found for " + key);
    }
    return null;
  }


  public List get(String key)
  {
    List values = new Vector();
    for (Iterator mappingIt = _regexpMapping.iterator();
         mappingIt.hasNext();) {
      RegexpPair rp = (RegexpPair) mappingIt.next();
      if (rp._first.match(key)) {
        values.add(rp._second);
      }
    }
    return values;
  }

  private class RegexpPair
  {
    public RE _first;
    public String _second;
    RegexpPair(String first, String second)
      throws RESyntaxException
    {
      _first  = new RE(first);
      _second = second;
    }
  }
}

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
    super(sb, fileName);

    _log = (LoggingService) sb.getService(this, LoggingService.class, null);

    _regexpMapping = new Vector();
    for (Iterator stringPairsIt = _mapping.iterator(); 
         stringPairsIt.hasNext();) {
      StringPair stringPair = (StringPair) stringPairsIt.next();
      _regexpMapping.add(new RegexpPair(stringPair._first, 
                                        stringPair._second));
    }
  }

  synchronized public String functionalGet(String key)
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


  synchronized public List get(String key)
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

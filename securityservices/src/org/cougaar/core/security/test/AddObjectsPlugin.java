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
package org.cougaar.core.security.test;

import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.LoggingService;

import java.io.Serializable;
import java.util.List;

/**
 * This class just adds some objects to the blackboard. 
 */
public class AddObjectsPlugin extends ComponentPlugin {

  private LoggingService  _log;
  private int             _maxObjects = 50000;
  private int             _objSize    = 1000;

  public void setParameter(Object o) {
    if (!(o instanceof List)) {
      throw new IllegalArgumentException("Expecting a List parameter " +
                                         "instead of " + 
                                         ( (o == null)
                                           ? "null" 
                                           : o.getClass().getName() ));
    }

    List l = (List) o;
    if (l.size() != 0) {
      _maxObjects = Integer.parseInt(l.remove(0).toString());
    } // end of if (l.size() != 0)
    if (l.size() != 0) {
      _objSize = Integer.parseInt(l.remove(0).toString());
    } // end of if (l.size() != 0)
  }

  protected void execute() {
  }

  /**
   * Sets up the AggregationQuery and event subscriptions.
   */
  protected void setupSubscriptions() {
    _log = (LoggingService)
	getServiceBroker().getService(this, LoggingService.class, null);

    System.out.println("adding objects to blackboard service");
    BlackboardService bbs = getBlackboardService();
    for (int i = 0; i < _maxObjects; i++) {
      bbs.publishAdd(new BigObject(_objSize));
      if (i % 1000 == 999) {
        System.out.println("Added " + (i+1) + " " + _objSize + " byte objects");
      }
    } // end of for (int i = 0; i < _maxObjects; i++)
    
  }

  private static class BigObject implements Serializable {
    byte buf[];
    public BigObject(int size) {
      buf = new byte[size];
      for (int i = 0; i < buf.length; i++) {
        buf[i] = (byte) i;
      } // end of for (int i = 0; i < buf.length; i++)
    }
  }
}

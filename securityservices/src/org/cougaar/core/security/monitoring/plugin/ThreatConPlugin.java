/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects
 *  Agency (DARPA).
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 *
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 *
 * </copyright>
 *
 * CHANGE RECORD
 * -
 */
package org.cougaar.core.security.monitoring.plugin;


import org.cougaar.core.adaptivity.OperatingMode;
import org.cougaar.core.adaptivity.OperatingModeImpl;
import org.cougaar.core.adaptivity.OMCRangeList;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.util.UnaryPredicate;

import java.util.Collection;
import java.util.Iterator;
import java.util.List;

/**
 * This plugin manages the threatcon.
 */
public class ThreatConPlugin extends ComponentPlugin {
  private LoggingService _log;

  private static final String _omName =
  "org.cougaar.core.security.monitoring.PERCEIVED_THREAT_LEVEL";
  private static final String[] OPERATING_MODE_VALUES = {"LOW", "HIGH"};
  private static final OMCRangeList OMRANGE = new OMCRangeList(OPERATING_MODE_VALUES);

  private final UnaryPredicate _threatConPredicate = 
    new UnaryPredicate() {
      public boolean execute(Object o) {
        if (o instanceof OperatingMode) {
	  OperatingMode om = (OperatingMode) o;
	  if (_omName.equals(om.getName())) {
	    return true;
	  }
	}
	return false;
      }
    };

  public void setParameter(Object o) {
    if (!(o instanceof List)) {
      throw new IllegalArgumentException("Expecting a List parameter " +
                                         "instead of " + 
                                         ( (o == null)
                                           ? "null" 
                                           : o.getClass().getName() ));
    }

    List l = (List) o;
  }

  protected void setupSubscriptions() {
    ServiceBroker sb = getServiceBroker();
    _log = (LoggingService)sb.getService(this, LoggingService.class, null);
    rehydrate();
  }

  public void execute() {
  }

  private void rehydrate() {
    Collection c = getBlackboardService().query(_threatConPredicate);
    if (c.isEmpty()) {
      if (_log.isInfoEnabled()) {
        _log.info("No rehydration. Publish Add operating mode: " + _omName);
      }
      // publishAdd the operating mode.
      OperatingMode om = new OperatingModeImpl(_omName, OMRANGE);
      om.setValue("HIGH");
      getBlackboardService().publishAdd(om);
    }
    else {
      OperatingMode om = (OperatingMode) c.iterator().next();
      if (_log.isInfoEnabled()) {
        _log.info("Rehydrating. " + _omName + "=" + om.getValue());
      }
    }
  }
}

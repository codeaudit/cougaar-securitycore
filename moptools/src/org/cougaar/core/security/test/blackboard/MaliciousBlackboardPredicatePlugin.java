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


package org.cougaar.core.security.test.blackboard;


import org.cougaar.glm.ldm.oplan.OrgActivity;
import org.cougaar.util.UnaryPredicate;

import java.util.Collection;
import java.util.Iterator;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;


/**
 * This plugin should not have any Blackboard Permissions for OrgActivities
 *
 * @author ttschampel
 */
public class MaliciousBlackboardPredicatePlugin extends AbstractBlackboardPlugin {
  private static Logger _log;
  static {
    _log = LoggerFactory.getInstance().createLogger(MaliciousBlackboardPredicatePlugin.class);
  }

  private UnaryPredicate evilPredicate = new UnaryPredicate() {
    public boolean execute(Object o) {
      return true;
    }
  };

  private UnaryPredicate moreEvilPredicate = new UnaryPredicate() {
    public boolean execute(Object o) {
      Object obj = o;
      boolean bol = false;

      if (obj instanceof OrgActivity) {
        obj = null;
        totalRuns++;
        failures++;
	if (_log.isWarnEnabled()) {
	  _log.warn("Able to get OrgActivity in predicate");
	}
        createIDMEFEvent(pluginName, "Able to get OrgActivity in predicate");
        bol = true;
      }


      return bol;
    }
  };

  /**
   * DOCUMENT ME!
   */
  public void load() {
    super.load();
    this.setPluginName("MaliciousBlackboardPredicatePlugin");
  }


  /**
   * Try all of the evil queries
   */
  protected void queryBlackboard() {
    Collection coll1 = getBlackboardService().query(evilPredicate);
    this.totalRuns++;
    boolean gotOrgActivity = false;
    Iterator iterator = coll1.iterator();
    while (iterator.hasNext()) {
      if (iterator.next() instanceof OrgActivity) {
        gotOrgActivity = true;
        break;
      }
    }

    if (gotOrgActivity) {
      if (_log.isWarnEnabled()) {
	_log.warn("Got an OrgActivity from predicate");
      }
      this.failures++;
      this.createIDMEFEvent(pluginName, "Got an OrgActivity from predicate");
    } else {
      this.successes++;

    }

    Collection coll2 = getBlackboardService().query(moreEvilPredicate);
  }
}

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


/*
 * Created on Jun 4, 2003
 *
 *
 */
package org.cougaar.core.security.test.blackboard;


import java.util.Collection;
import java.util.Iterator;


/**
 * DOCUMENT ME!
 *
 * @author ttschampel
 */
public class LegitimateBlackboardPlugin extends AbstractBlackboardPlugin {
  /**
   * DOCUMENT ME!
   */
  public void load() {
    super.load();
    setPluginName("LegitimateBlackboardPlugin");
  }


  /**
   * Query for org activities and produce idmef event when  org activities
   * should be present, but can't get any through querying the blacboard
   */
  protected void queryBlackboard() {
    Collection orgActivities = getBlackboardService().query(this.orgActivityPredicate);
    Iterator iter = orgActivities.iterator();
    this.totalRuns++;
    if (iter.hasNext()) {
      //success	
      this.successes++;
    } else {
      //failure
      this.failures++;
      this.createIDMEFEvent(pluginName, "Can't access OrgActivity object");
    }
  }
}

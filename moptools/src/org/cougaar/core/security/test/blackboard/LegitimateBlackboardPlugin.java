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

import org.cougaar.core.util.UID;
import org.cougaar.glm.ldm.oplan.OplanFactory;
import org.cougaar.glm.ldm.oplan.OrgActivity;
import org.cougaar.glm.ldm.oplan.OrgActivityImpl;
import org.cougaar.core.service.UIDService;


/**
 * DOCUMENT ME!
 *
 * @author ttschampel
 */
public class LegitimateBlackboardPlugin extends AbstractBlackboardPlugin {
  private UIDService uidService;

  /**
   * DOCUMENT ME!
   */
  public void load() {
    super.load();
    setPluginName("LegitimateBlackboardPlugin");
  }

  /**
   * set uid service
   *
   * @param service UIDService
   */
  public void setUIDService(UIDService service) {
    uidService = service;
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
      // Try to add OrgActivity objects to the blackboard
      UID oplanId = uidService.nextUID();
      OrgActivity oa = OplanFactory.newOrgActivity("foobarActivityType",
						   "foobarActivityName",
						   "foobarOrgId", 
						   oplanId);
      try {
	this.totalRuns++;
	getBlackboardService().publishAdd(oa);
	this.successes++;
      }
      catch (Exception e) {
	if (logging.isWarnEnabled()) {
	  logging.warn("Unable to publishAdd OrgActivity!");
	}
	this.failures++;
	this.createIDMEFEvent(pluginName, "Can't access OrgActivity object");
      }
      // Try again
      orgActivities = getBlackboardService().query(this.orgActivityPredicate);
      iter = orgActivities.iterator();
      if (!iter.hasNext()) {
	//failure
	this.failures++;
	this.createIDMEFEvent(pluginName, "Can't access OrgActivity object");
      }
      try {
	this.totalRuns++;
	getBlackboardService().publishRemove(oa);
	this.successes++;
      }
      catch (Exception e) {
	if (logging.isWarnEnabled()) {
	  logging.warn("Unable to publishRemove OrgActivity!");
	}
	this.failures++;
	this.createIDMEFEvent(pluginName, "Can't access OrgActivity object");
      }
    }
  }
}

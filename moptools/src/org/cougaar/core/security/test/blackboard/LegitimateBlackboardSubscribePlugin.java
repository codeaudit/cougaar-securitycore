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


import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.util.UID;
import org.cougaar.glm.ldm.oplan.OrgActivity;
import org.cougaar.glm.ldm.oplan.OrgActivityImpl;
import org.cougaar.glm.ldm.oplan.OplanFactory;
import org.cougaar.util.UnaryPredicate;

import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;


/**
 * Subscribes to changes in OrgActivities (Changes are published by itself).
 * This plugin should have Query access and modify access to the OrgActivity
 * Objects on the Blackboard.
 *
 * @author ttschampel
 */
public class LegitimateBlackboardSubscribePlugin extends AbstractBlackboardPlugin {
  private IncrementalSubscription orgSubs = null;
  private UID modId = null;
  private static final String ACTIVITY_NAME =
	"LegitimateBlackboardSubscribePlugingActivityName";
  private static final String ACTIVITY_TYPE =
	"LegitimateBlackboardSubscribePlugingActivityType";

  /** Predicate for OrgActivity objects */
  protected UnaryPredicate legitOrgActivityPredicate = new UnaryPredicate() {
    public boolean execute(Object o) {
      if (o instanceof OrgActivity) {
	OrgActivity oa = (OrgActivity) o;
	if (ACTIVITY_NAME.equals(oa.getActivityName())) {
	  return true;
	}
      }
      return false;
    }
  };

  /**
   * DOCUMENT ME!
   */
  public void load() {
    super.load();
    this.setPluginName("LegitimateBlackboardSubcribePlugin");
  }


  /**
   * DOCUMENT ME!
   */
  public void setupSubscriptions() {
    super.setupSubscriptions();
    publishAddOrgActivity();
    orgSubs = (IncrementalSubscription)
       getBlackboardService().subscribe(legitOrgActivityPredicate);
  }


  /**
   * DOCUMENT ME!
   */
  public void execute() {
    super.execute();
    if(!this.wasAwakened()){
    	checkModified();
    }
  }

  private void checkModified() {
    if (modId != null) {
      boolean foundIt = false;
      Enumeration enumeration = orgSubs.getChangedList();
      while (enumeration.hasMoreElements()) {
        OrgActivity orgActivity = (OrgActivity) enumeration.nextElement();
        if (orgActivity.getUID().equals(modId)) {
          foundIt = true;
          break;
        }
      }

      if (foundIt) {
        this.successes++;
      } else {
        this.failures++;
        if (logging.isDebugEnabled()) {
          logging.debug("Was unable to  modify OrgActivity Object!");
        }

        this.createIDMEFEvent(pluginName,
          "Not Able to modify OrgActivity on the Blackboard!");
      }
    }
  }


  /**
   * Try to modify a org activity
   */
  protected void queryBlackboard() {
    Collection collection = this.getBlackboardService().query(this.legitOrgActivityPredicate);
    Iterator iterator = collection.iterator();
    if (iterator.hasNext()) {
      OrgActivity orgActivity = (OrgActivity) iterator.next();
      try {
        orgActivity.setActivityName(ACTIVITY_NAME);
      }
      catch (SecurityException e) {
        if (logging.isWarnEnabled()) {
          logging.warn("queryBlackboard: unable to set activity name - OrgActivity: " + e.getMessage());
        }
      }
      try {
	getBlackboardService().publishChange(orgActivity);
      }
      catch (SecurityException e) {
        if (logging.isWarnEnabled()) {
          logging.warn("queryBlackboard: unable to publishChange OrgActivity: " + e.getMessage());
        }
      }
      this.modId = orgActivity.getUID();
      this.totalRuns++;

    } else {
      this.modId = null;
    }
  }

  private void publishAddOrgActivity() {
    if (logging.isDebugEnabled()) {
      logging.debug("publishAddOrgActivity");
    }
    OrgActivity oa = OplanFactory.newOrgActivity(pluginName, uidService.nextUID());
    oa.setActivityName(ACTIVITY_NAME);
    oa.setActivityType(ACTIVITY_TYPE);
    oa.setUID(uidService.nextUID());
    MessageAddress ma = null;
    AgentIdentificationService ais = (AgentIdentificationService)
      getServiceBroker().getService(this, AgentIdentificationService.class, null);
    if(ais != null) {
      ma = ais.getMessageAddress(); 
      getServiceBroker().releaseService(this, AgentIdentificationService.class, ais);
    }
    else {
      if (logging.isWarnEnabled()) {
	logging.warn("Unable to get AgentIdentificationService");
      }
    }
    ((OrgActivityImpl)oa).setOwner(ma);

    try {
      this.totalRuns++;
      getBlackboardService().publishAdd(oa);
      this.successes++;
    }
    catch (Exception e) {
      if (logging.isWarnEnabled()) {
	logging.warn("Unable to publishAdd OrgActivity!", e);
      }
      this.failures++;
    }
  }
}

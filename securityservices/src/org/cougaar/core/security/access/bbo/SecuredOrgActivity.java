/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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
package org.cougaar.core.security.access.bbo;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.io.Serializable;
import java.util.HashMap;
import java.security.Permission;

import org.cougaar.core.util.OwnedUniqueObject;
import org.cougaar.core.util.UID;
import org.cougaar.core.util.UniqueObject;

import org.cougaar.core.mts.MessageAddress;

import org.cougaar.glm.ldm.oplan.OrgActivity;
import org.cougaar.glm.ldm.oplan.TimeSpan;

import org.cougaar.planning.ldm.plan.Location;
import org.cougaar.planning.ldm.plan.LocationScheduleElement;
import org.cougaar.planning.ldm.plan.LocationScheduleElementImpl;
import org.cougaar.planning.ldm.plan.TaggedLocationScheduleElement;
import org.cougaar.planning.ldm.plan.Transferable;

import org.cougaar.glm.ldm.plan.GeolocLocation;
import org.cougaar.glm.ldm.plan.NewGeolocLocation;

import org.cougaar.core.security.auth.SecuredObject;
import org.cougaar.core.security.auth.ObjectContext;
import org.cougaar.core.security.auth.ObjectContextUtil;
import org.cougaar.core.security.auth.BlackboardObjectPermission;

public final class SecuredOrgActivity implements OrgActivity, SecuredObject {
  private        OrgActivity     _org;
  private final  ObjectContext   _context;
  private static SecurityManager _sm = System.getSecurityManager();

  private final static java.security.Permission CREATE =
    new BlackboardObjectPermission(OrgActivity.class.getName(), "create");
  // NOTE: since read is implied by the Blackboard access permissions
  //       (add, change, query, remove), it's not necessary to doing a 
  //       check permission read.  thus, the commented checkPermission(READ).
  private final static java.security.Permission READ =
    new BlackboardObjectPermission(OrgActivity.class.getName(), "read");
  private final static java.security.Permission WRITE =
    new BlackboardObjectPermission(OrgActivity.class.getName(), "write");

  public SecuredOrgActivity(OrgActivity org) {
    _context = ObjectContextUtil.createContext(org);
    _org = org;
    checkPermission(CREATE);
  }

  private void checkPermission(Permission p) {
    if (_sm != null) {
      _sm.checkPermission(p, this);
    }
  }

  public String getActivityType() {
    //checkPermission(READ);
    return _org.getActivityType();
  }

  public void setActivityType(String activityType) {
    checkPermission(WRITE);
    _org.setActivityType(activityType);
  }

  public String getActivityName() {
    //checkPermission(READ);
    return _org.getActivityName();
  }

  public void setActivityName(String activityName) {
    checkPermission(WRITE);
    _org.setActivityName(activityName);
  }

  public String getOrgID() {
    //checkPermission(READ);
    return _org.getOrgID();
  }

  public void setOrgID(String orgID) {
    checkPermission(WRITE);
    _org.setOrgID(orgID);
  }

  public UID getOrgActivityId() {
    //checkPermission(READ);
    return _org.getOrgActivityId();
  }

  public void setOrgActivityId(UID uid) {
    checkPermission(WRITE);
    _org.setOrgActivityId(uid);
  }

  public void setOplanUID(UID oplanUID) {
    checkPermission(WRITE);
    _org.setOplanUID(oplanUID);
  }

  /** @deprecated Use setOplanUID */
  public void setOplanID(UID oplanUID) {
    checkPermission(WRITE);
    _org.setOplanUID(oplanUID);
  }

  public String getOpTempo() {
    //checkPermission(READ);
    return _org.getOpTempo();
  }

  public void setOpTempo(String opTempo) {
    checkPermission(WRITE);
    _org.setOpTempo(opTempo);
  }

  public GeolocLocation getGeoLoc() {
    //checkPermission(READ);
    return _org.getGeoLoc();
  }

  public void setGeoLoc(GeolocLocation geoLoc) {
    checkPermission(WRITE);
    _org.setGeoLoc(geoLoc);
  }

  public String getActivityItem(String key) {
    //checkPermission(READ);
    return _org.getActivityItem(key);
  }

  public void addActivityItem(String key, String value) {
    checkPermission(WRITE);
    _org.addActivityItem(key, value);
  }

  public void modifyActivityItem(String key, String value) {
    checkPermission(WRITE);
    _org.modifyActivityItem(key, value);
  }

  public HashMap getItems() {
    try {
      checkPermission(WRITE);
      return _org.getItems();
    } catch (SecurityException e) {
      //checkPermission(READ);
      // this should really be changed to:
      // return Collections.unmodifiableMap(_org.getItems());
      return new HashMap(_org.getItems());
    }
  }


  /** convert OPlan-centric location and timespan to 
   * standard ALPish (logplan) schedule element 
   * @return a LocationScheduleElement or null, if a locationscheduleelement 
   * cannot be constructed (e.g. no schedule, no location).
   **/
  public LocationScheduleElement getNormalizedScheduleElement() {
    //checkPermission(READ);
    return _org.getNormalizedScheduleElement();
  }

  // Cloneable + Transferable:

  public Object clone() {
    //checkPermission(READ);
    return new SecuredOrgActivity((OrgActivity)_org.clone());
  }

  // SecuredObject
  public ObjectContext getObjectContext() {
    return _context;
  }

  // UniqueObject interface
  public UID getUID() {
    //checkPermission(READ);
    return _org.getUID();
  }

  public void setUID(UID uid) {
    // NOTE:
    // setUID throws a RuntimeException if called more than once.
    // so there isn't a need to perform a WRITE permission check
    //
    //checkPermission(WRITE);
    _org.setUID(uid);
  }

  // Transferable interface
  public MessageAddress getSource() {
    //checkPermission(READ);
    return _org.getSource();
  }

  public boolean isFrom(MessageAddress src) {
    //checkPermission(READ);
    return _org.isFrom(src);
  }

  public boolean same(Transferable other) {
    //checkPermission(READ);
    return _org.same(other);
  }

  public void setAll(Transferable other) {
    checkPermission(WRITE);
    _org.setAll(other);
  }

  // TimeSpan interface
  public long getStartTime() {
    //checkPermission(READ);
    return _org.getStartTime();
  }

  public long getEndTime() {
    //checkPermission(READ);
    return _org.getEndTime();
  }

  // OplanContributor

  /** @deprecated Use getOplanUID */
  public UID getOplanID() {
    //checkPermission(READ);
    return _org.getOplanUID();
  }

  public UID getOplanUID() {
    //checkPermission(READ);
    return _org.getOplanUID();
  }

  public TimeSpan getTimeSpan() {
    try {
      checkPermission(WRITE);
      return _org.getTimeSpan();
    } catch (SecurityException e) {
      //checkPermission(READ);
      return (TimeSpan) _org.getTimeSpan().clone();
    }
  }

  public void setTimeSpan(TimeSpan ts) {
    checkPermission(WRITE);
    _org.setTimeSpan(ts);
  }

  public boolean equals(Object o) {
    if (!(o instanceof SecuredOrgActivity)) {
      return false;
    }
    SecuredOrgActivity soa = (SecuredOrgActivity) o;
    return getUID().equals(soa.getUID()) &&
      getObjectContext().equals(soa.getObjectContext());
  }

  public int hashCode() {
    return getUID().hashCode();
  }
}


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
package org.cougaar.core.security.monitoring.blackboard;


import org.cougaar.core.util.UID;
import org.cougaar.lib.aggagent.query.ResultSetDataAtom;
import org.cougaar.lib.aggagent.session.IncrementFormat;
import org.cougaar.lib.aggagent.session.SubscriptionAccess;
import org.cougaar.lib.aggagent.session.UpdateDelta;
import org.cougaar.util.ConfigFinder;

import java.util.Collection;
import java.util.Iterator;

import edu.jhuapl.idmef.IDMEF_Message;


public class FormatEvent implements IncrementFormat {
  // IncrementFormat API
  public void encode(UpdateDelta out, SubscriptionAccess sacc) {
    Collection addTo = out.getAddedList();
    Collection added = sacc.getAddedCollection();
    out.setReplacement(true);

    if (added == null) {
      return;
    }

    Iterator iter = added.iterator();
    ConfigFinder cf = ConfigFinder.getInstance();
    IDMEF_Message.setDtdFileLocation(cf.locateFile("idmef-message.dtd").toString());
    while (iter.hasNext()) {
      Event event = (Event) iter.next();
      ResultSetDataAtom da = new ResultSetDataAtom();
      UID uid = event.getUID();
      da.addIdentifier("owner", uid.getOwner());
      da.addIdentifier("id", String.valueOf(uid.getId()));
      da.addValue("source", event.getSource().toAddress());
      da.addValue("event", event.getEvent().toString());
      addTo.add(da);
    }
  }
}

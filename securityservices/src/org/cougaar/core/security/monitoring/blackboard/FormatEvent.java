
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


import java.util.Enumeration;
import java.util.Collection;
import java.util.Iterator;


import edu.jhuapl.idmef.IDMEFTime;
import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.IDMEF_Message;
import edu.jhuapl.idmef.Alert;

// Cougaar core services
import org.cougaar.core.mts.MessageAddress;

import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.service.UIDService;


import org.cougaar.core.util.UID;
import org.cougaar.core.util.UniqueObject;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.adaptivity.OMCRangeList;
import org.cougaar.core.adaptivity.Condition;
import org.cougaar.core.mts.MessageAddress;


import org.cougaar.core.security.monitoring.idmef.IdmefMessageFactory;
import org.cougaar.core.security.monitoring.idmef.RegistrationAlert;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.security.monitoring.blackboard.EventImpl;

// Cougaar overlay
import org.cougaar.core.security.constants.IdmefClassifications;

import org.cougaar.multicast.AttributeBasedAddress;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.util.ConfigFinder;

import org.cougaar.lib.aggagent.query.AlertDescriptor;
import org.cougaar.lib.aggagent.query.AggregationQuery;
import org.cougaar.lib.aggagent.query.QueryResultAdapter;
import org.cougaar.lib.aggagent.query.ResultSetDataAtom;
import org.cougaar.lib.aggagent.query.ScriptSpec;
import org.cougaar.lib.aggagent.query.AggregationResultSet;

import org.cougaar.lib.aggagent.session.UpdateDelta;
import org.cougaar.lib.aggagent.session.SessionManager;
import org.cougaar.lib.aggagent.session.XMLEncoder;
import org.cougaar.lib.aggagent.session.SubscriptionAccess;
import org.cougaar.lib.aggagent.session.IncrementFormat;

import org.cougaar.lib.aggagent.util.Enum.QueryType;
import org.cougaar.lib.aggagent.util.Enum.Language;
import org.cougaar.lib.aggagent.util.Enum.AggType;
import org.cougaar.lib.aggagent.util.Enum.ScriptType;
import org.cougaar.lib.aggagent.util.Enum.UpdateMethod;
import org.cougaar.lib.aggagent.util.Enum.XmlFormat;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.w3c.dom.Document;


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

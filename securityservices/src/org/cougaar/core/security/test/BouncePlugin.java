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

import java.util.List;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Calendar;
import java.util.TimeZone;
import java.util.Enumeration;
import java.util.Collection;
import java.util.HashSet;
import java.util.Hashtable;

import java.io.Serializable;
import java.io.StringReader;
import java.io.IOException;

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
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;

import org.cougaar.core.util.UID;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.adaptivity.OMCRangeList;
import org.cougaar.core.adaptivity.Condition;
import org.cougaar.core.mts.MessageAddress;

import org.cougaar.core.security.crypto.ldap.KeyRingJNDIRealm;
import org.cougaar.core.security.monitoring.idmef.IdmefMessageFactory;
import org.cougaar.core.security.monitoring.idmef.RegistrationAlert;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.MRAgentLookUp;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.security.monitoring.blackboard.MRAgentLookUpReply;
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

public class BouncePlugin extends ComponentPlugin {
  /**
   * for set/get DomainService
   */
  protected DomainService  _domainService;


  private LoggingService  _log;
  private Hashtable       _sent = new Hashtable();
  private UnaryPredicate  _pred = new UnaryPredicate() {
      public boolean execute(Object obj) {
        return (obj instanceof CmrRelay &&
                ((CmrRelay) obj).getContent() instanceof UID);
      }
    };
  private IncrementalSubscription _subscription;
  private MessageAddress _destination;

  private CmrFactory _cmrFactory;
  private String     _id;
  private int        _sendCount = 10;

  /**
   * Used by the binding utility through reflection to set my DomainService
   */
  public void setDomainService(DomainService aDomainService) {
    _domainService = aDomainService;
  }

  /**
   * Used by the binding utility through reflection to get my DomainService
   */
  public DomainService getDomainService() {
    return _domainService;
  }

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
      _id = l.remove(0).toString();
    }
    if (l.size() != 0) {
      _destination =  MessageAddress.getMessageAddress(l.remove(0).toString());
    }
    if (l.size() != 0) {
      _sendCount = Integer.parseInt(l.remove(0).toString());
    } // end of else
  }

  protected void execute() {
    if (_subscription.hasChanged()) {
      Enumeration added = _subscription.getAddedList();
      BlackboardService bbs = getBlackboardService();
      while (added.hasMoreElements()) {
        CmrRelay cmr = (CmrRelay) added.nextElement();
        UID contents = (UID) cmr.getContent();
        CmrRelay sentCmr = (CmrRelay) _sent.get(contents);
        if (sentCmr != null) {
          _sent.remove(contents);
          bbs.publishRemove(sentCmr);
        } else if (_sent.get(cmr.getUID()) != null) {
          continue;
        } // end of if (_sent.get(cmr.getUID()) == null)
        
        bbs.publishRemove(cmr);
        Object o = cmr.getUID();

	MessageAddress ci = null;
	if (_destination != null) {
	  ci = _destination;
	}
	else {
	  ci = cmr.getSource();
	}
	CmrRelay relay = (CmrRelay) _cmrFactory.newCmrRelay(o, ci);
        _sent.put(relay.getUID(), relay);
        bbs.publishAdd(relay);
      } // end of while (added.hasMoreElements())
    } // end of if (_subscription.hasChanged())
    
  }

  /**
   * Sets up the AggregationQuery and event subscriptions.
   */
  protected void setupSubscriptions() {
    _log = (LoggingService)
	getServiceBroker().getService(this, LoggingService.class, null);

    BlackboardService bbs = getBlackboardService();

    _subscription = (IncrementalSubscription) bbs.subscribe(_pred);

    DomainService        ds           = getDomainService(); 
    _cmrFactory                        = (CmrFactory) ds.getFactory("cmr");

    if (_id != null && _destination != null) {
      for (int i = 0; i < _sendCount; i++) {
	UID uid = new UID(_id, i);
	CmrRelay relay = _cmrFactory.newCmrRelay(uid, _destination);
	_sent.put(relay.getUID(), relay);
	bbs.publishAdd(relay);
      } // end of for (int i = 0; i < _sent.length; i++)
    }
  }

}

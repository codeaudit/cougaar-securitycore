/*
 * <copyright>
 *  Copyright 2002-2003 Cougaar Software, Inc.
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
package org.cougaar.core.security.test.coordinator;

import javax.agent.JasBean;

import java.io.IOException;

import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import kaos.core.service.directory.KAoSAgentDirectoryServiceProxy;
import kaos.core.service.util.cougaar.CougaarLocator;

import safe.util.CougaarServiceRoot;
import safe.util.TransactionLock;

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.coordinator.ThreatConActionInfo;
import org.cougaar.core.security.provider.SecurityComponent;
import org.cougaar.core.security.policy.builder.KAoSAgentOntologyConnection;
import org.cougaar.core.security.policy.builder.Main;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.ThreadService;
import org.cougaar.util.UnaryPredicate;

import ri.JasBeanImpl;

public class UpdatePolicyPlugin
  extends ComponentPlugin
{
  private static String HIGH_POLICY = "OwlCoordinatorHighPolicy";
  private static String LOW_POLICY  = "OwlCoordinatorLowPolicy";
  private static String BOOT_POLICY = "OwlBootPolicyList";
  private static int    TIMEOUT     = 10000;
  
  private Object                         _threatLock = new Object();
  private String                         _requestedThreatLevel = null;
  private List                           _threatQueue = new Vector();

  private boolean                        _initialized = false;
  private ServiceBroker                  _sb;
  private String                         _policyManager;
  private String                         _myAgentName;
  private BlackboardService              _bbs;
  private LoggingService                 _log;
  private KAoSAgentOntologyConnection    _kds;
  private IncrementalSubscription        _threatAction;


  private ThreadService                  _ts;
  private TransactionLock                _tlock;

  private UnaryPredicate                 _threatDetector
    = new UnaryPredicate() {
        public boolean execute(Object o) {
          return o instanceof ThreatConActionInfo;
        }
      };

  public void setParameter(Object o)
  {
    if (!(o instanceof List) || ((List) o).size() < 1) {
      throw new IllegalArgumentException("could not initialize component - no arguments");
    }
    List l = (List) o;
    _policyManager = (String) l.get(0);
  }

  public void load() {
    super.load();
    _sb = getBindingSite().getServiceBroker();
    _log = (LoggingService) _sb.getService(this,
                                           LoggingService.class,
                                           null);
    _bbs = (BlackboardService) _sb.getService(this,
                                              BlackboardService.class,
                                              null);
    _tlock = new TransactionLock();
    AgentIdentificationService idService 
      = (AgentIdentificationService) _sb.getService(
                                                    this, 
                                                    AgentIdentificationService.class, 
                                                    null);
    _myAgentName = idService.getMessageAddress().toAddress();
    _sb.releaseService(this, AgentIdentificationService.class, idService);

    CougaarServiceRoot sr 
      = new CougaarServiceRoot(_sb, _bbs, _tlock, obtainEntityEnv());
    Object o = sr.getAgentDirectoryService();
    if (!(o instanceof KAoSAgentDirectoryServiceProxy)) {
      _log.error("got directory service of wrong class - " + 
                 (o == null ? null : o.getClass().getName()));
    }
    _kds = new KAoSAgentOntologyConnection((KAoSAgentDirectoryServiceProxy) o);
    new Thread(new PolicyRunner()).start();
  }

  protected void setupSubscriptions()
  {
    _threatAction
      = (IncrementalSubscription) blackboard.subscribe(_threatDetector);
  }

  private boolean firstTime = true;
  public void execute()
  {
    if (_log.isDebugEnabled()) {
      _log.debug("In execute");
    }
    boolean doNotify = false;
    synchronized (_threatLock) {
      for (Iterator threatIt = _threatAction.getAddedCollection().iterator();
           threatIt.hasNext();) {
        ThreatConActionInfo threatAction = (ThreatConActionInfo) threatIt.next();
        if (threatAction.getDiagnosis().equals(ThreatConActionInfo.START)) {
          _threatQueue.add(threatAction);
          _requestedThreatLevel = threatAction.getLevel();
          doNotify = true;
        }
      }
      for (Iterator threatIt = _threatAction.getAddedCollection().iterator();
           threatIt.hasNext();) {
        ThreatConActionInfo threatAction = (ThreatConActionInfo) threatIt.next();
        _requestedThreatLevel = threatAction.getLevel();
        if (threatAction.getDiagnosis().equals(ThreatConActionInfo.START)) {
          doNotify = true;
        }
      }
      if (doNotify) {
        if (_log.isDebugEnabled()) {
          _log.debug("Coordinator requesting threat level set at " 
                     + _requestedThreatLevel);
        }
        _threatLock.notify();
      }
    }
  }

  private JasBean obtainEntityEnv()
  {
    JasBeanImpl jasBean = new JasBeanImpl();
    CougaarLocator policyLocator = new CougaarLocator(_policyManager);
    jasBean.set(CougaarLocator.UIC, _myAgentName);
    jasBean.set(CougaarServiceRoot.DOMAIN_MANAGER_LOCATOR, 
                new CougaarLocator(_policyManager));
    jasBean.set(CougaarServiceRoot.DOMAIN_MANAGER_NICKNAME, _policyManager);
    return jasBean;
  }

  private void commitPolicy(String policy)
    throws IOException
  {
    Main m = new Main();
    m.setPolicyFile(policy);
    m.setOntologyConnection(_kds);
    m.commitPolicies(false);
  }

  private class PolicyRunner
    implements Runnable
  {
    public void run()
    {
      if (_log.isDebugEnabled()) {
        _log.debug("Entering Policy thread");
      }
      try {
        commitPolicy(BOOT_POLICY);
      } catch (IOException ioe) {
        _log.fatal("UpdatPolicyPlugin failed to commit boot policies - canot proceed", ioe);
        return;
      }
      if (_log.isDebugEnabled()) {
        _log.debug("Domain Manager has policies");
      }
      String myThreatLevel = null;
      try {
        while (true) {
          String level;
          synchronized(_threatLock) {
            while (_threatQueue.isEmpty()) {
              _threatLock.wait();
            }
            if (_requestedThreatLevel.equals(myThreatLevel)) {
              if (_log.isDebugEnabled()) {
                _log.debug("I have responded to the coordinators request");
                _log.debug("Proceeding to mark requests as active");
              }
              _bbs.openTransaction();
              try {
                for (Iterator threatIt = _threatQueue.iterator();
                     threatIt.hasNext();) {
                  ThreatConActionInfo tcai = (ThreatConActionInfo) threatIt.next();
                  if (tcai.getLevel().equals(myThreatLevel)) {
                    tcai.setDiagnosis(ThreatConActionInfo.ACTIVE);
                    _bbs.publishAdd(tcai);
                  }
                  _threatQueue = new Vector();
                } 
              } finally {
                _bbs.closeTransaction();
              }
              continue;
            } else {
              level = _requestedThreatLevel;
            }
          } // synchronized(_threatLock)

          try {
            if (level.equals(ThreatConActionInfo.LOWDiagnosis)) {
              if (_log.isDebugEnabled()) {
                _log.debug("committing low policy");
              }
              commitPolicy(LOW_POLICY);
              myThreatLevel = ThreatConActionInfo.LOWDiagnosis;
              if (_log.isDebugEnabled()) {
                _log.debug("low policy committed");
              }
            } else {
              if (_log.isDebugEnabled()) {
                _log.debug("committing high policy");
              }
              commitPolicy(HIGH_POLICY);
              myThreatLevel = ThreatConActionInfo.HIGHDiagnosis;
              if (_log.isDebugEnabled()) {
                _log.debug("high policy committed");
              }
            }
          } catch(IOException ioe) {
            _log.error("Exception trying to commit policies", ioe);
            Thread.sleep(TIMEOUT);
          }
        }  // while(true)
      } catch (InterruptedException  ie) {
        _log.error("Inerrupted! - maybe I was thrashing?", ie);
      }
    } // public void run()
  }
}

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

import java.util.List;

import kaos.core.service.directory.KAoSAgentDirectoryServiceProxy;
import kaos.core.service.util.cougaar.CougaarLocator;

import safe.util.CougaarServiceRoot;
import safe.util.TransactionLock;

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.coordinator.ThreatConActionInfo;
import org.cougaar.core.security.provider.SecurityComponent;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.util.UnaryPredicate;

import ri.JasBeanImpl;

public class UpdatePolicyPlugin
  extends ComponentPlugin
{
  private boolean                        _initialized = false;
  private ServiceBroker                  _sb;
  private String                         _policyManager;
  private String                         _myAgentName;
  private LoggingService                 _log;
  private KAoSAgentDirectoryServiceProxy _kds;
  private IncrementalSubscription        _threatAction;
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
    BlackboardService bbs 
      = (BlackboardService) _sb.getService(this,
                                          BlackboardService.class,
                                          null);
    TransactionLock lock = new TransactionLock();
    AgentIdentificationService idService 
      = (AgentIdentificationService) _sb.getService(
                   this, 
                   AgentIdentificationService.class, 
                   null);
    _myAgentName = idService.getMessageAddress().toAddress();
    _sb.releaseService(this, AgentIdentificationService.class, idService);

    CougaarServiceRoot sr 
      = new CougaarServiceRoot(_sb, bbs, lock, obtainEntityEnv());
    Object o = sr.getAgentDirectoryService();
    if (!(o instanceof KAoSAgentDirectoryServiceProxy)) {
      _log.error("got directory service of wrong class - " + 
                 (o == null ? null : o.getClass().getName()));
    }
    _kds = (KAoSAgentDirectoryServiceProxy) o;
  }

  protected void setupSubscriptions()
  {
    _threatAction
      = (IncrementalSubscription) blackboard.subscribe(_threatDetector);
  }

  private boolean firstTime = true;
  public void execute()
  {
    if (firstTime) {
      firstTime = false;
      new Thread(new Runnable() {
          public void run()
          {
            try {
              List policies = _kds.getPolicies();
              if (policies == null) {
                _log.debug("no policies found");
              } else {
                _log.debug("policies size = " + policies.size());
              }
            } catch (Exception e) {
              _log.error("Oops...", e);
            }
          }
        }).start();
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

}
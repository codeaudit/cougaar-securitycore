/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 
package org.cougaar.core.security.pedigree;

import java.security.Permission;
import java.util.Map;
import java.util.WeakHashMap;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.services.auth.Pedigree;
import org.cougaar.core.security.services.auth.PedigreeService;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;


/**
 * @author srosset
 * This service manages the pedigree of blackboard objects.
 * This service must be instantiated once per agent.
 */
public class PedigreeServiceImpl
implements PedigreeService
{
  private ServiceBroker       serviceBroker;
  private Map                 pedigreeData = new WeakHashMap();
  private SecurityManager     securityManager;
  private Permission          pedigreePermission;
  private static Logger       _log;
  
  static {
    _log = LoggerFactory.getInstance().createLogger(PedigreeServiceImpl.class);
  }
  
  public PedigreeServiceImpl(ServiceBroker sb) {
    if (_log.isDebugEnabled()) {
      _log.debug("Instantiating " + getClass().getName());
    }
    serviceBroker = sb;
    securityManager = System.getSecurityManager();
    pedigreePermission = new PedigreePermission("setPedigree");
  }
  
  /* (non-Javadoc)
   * @see org.cougaar.core.security.services.auth.PedigreeService#getPedigree(java.lang.Object)
   */
  public Pedigree getPedigree(Object blackboardObject) {
    return (Pedigree)pedigreeData.get(blackboardObject);
  }
  
  /* (non-Javadoc)
   * @see org.cougaar.core.security.services.auth.PedigreeService#setPedigree(java.lang.Object, org.cougaar.core.security.services.auth.Pedigree)
   */
  public void setPedigree(Object blackboardObject, Pedigree pedigree) {
    try {
      if (securityManager != null) {
        securityManager.checkPermission(pedigreePermission);
      }
      synchronized (pedigreeData) {
        pedigreeData.put(blackboardObject, pedigree);
      }
    }
    catch (SecurityException e) {
      if (_log.isWarnEnabled()) {
        _log.warn("Unable to set Pedigree");
      }
    }
  }
  
  /* (non-Javadoc)
   * @see org.cougaar.core.security.services.auth.PedigreeService#removePedigree(java.lang.Object)
   */
  public void removePedigree(Object blackboardObject) {
    if (_log.isDebugEnabled()) {
      _log.debug("remove Pedigree of " + blackboardObject);
    }
    try {
      if (securityManager != null) {
        securityManager.checkPermission(pedigreePermission);
      }
      synchronized(pedigreeData) {
        pedigreeData.remove(blackboardObject);
      }
    }
    catch (SecurityException e) {
      if (_log.isWarnEnabled()) {
        _log.warn("Unable to remove Pedigree");
      }
    }
    
  }
}

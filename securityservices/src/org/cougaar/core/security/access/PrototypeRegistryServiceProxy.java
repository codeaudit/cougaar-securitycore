/**
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
 *
 */

package org.cougaar.core.security.access;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.planning.ldm.LatePropertyProvider;
import org.cougaar.planning.ldm.PropertyProvider;
import org.cougaar.planning.ldm.PrototypeProvider;
import org.cougaar.planning.ldm.asset.Asset;
import org.cougaar.planning.ldm.asset.PropertyGroup;
import org.cougaar.planning.service.PrototypeRegistryService;
import org.cougaar.util.StateModelException;

import org.cougaar.core.security.auth.ExecutionContext;

import java.util.Collection;

// this class is a proxy for the PrototypeRegistryService
class PrototypeRegistryServiceProxy extends SecureServiceProxy 
  implements PrototypeRegistryService {
  private final PrototypeRegistryService _prs;
  private final Object _requestor;
  
  public PrototypeRegistryServiceProxy(PrototypeRegistryService prs, Object requestor, ServiceBroker sb) {
    super(sb);
    _prs = prs;
    _requestor = requestor;
  }
  
  public void addLatePropertyProvider(LatePropertyProvider lpp) {
    _prs.addLatePropertyProvider(new SecureLatePropertyProvider(lpp, _scs.getExecutionContext()));
  }
            
  public void addPropertyProvider(PropertyProvider prov) {
    _prs.addPropertyProvider(new SecurePropertyProvider(prov, _scs.getExecutionContext()));
  }
            
  public void addPrototypeProvider(PrototypeProvider prov) {
    _prs.addPrototypeProvider(new SecurePrototypeProvider(prov, _scs.getExecutionContext()));
  }
            
  public void cachePrototype(String aTypeName, Asset aPrototype) {
    _prs.cachePrototype(aTypeName, aPrototype);
  }

  public void fillProperties(Asset anAsset) {
    _prs.fillProperties(anAsset);
  }

  public int getCachedPrototypeCount() {
    return _prs.getCachedPrototypeCount();
  }
            
  public int getPropertyProviderCount() {
    return _prs.getPropertyProviderCount();
  }
            
  public Asset getPrototype(String aTypeName) {
    return _prs.getPrototype(aTypeName);
  }

  public Asset getPrototype(String aTypeName, Class anAssetClass) {
    return _prs.getPrototype(aTypeName, anAssetClass);
  }

  public int getPrototypeProviderCount() {
    return _prs.getPrototypeProviderCount();
  }
            
  public boolean isPrototypeCached(String aTypeName) {
    return _prs.isPrototypeCached(aTypeName);
  }

  public PropertyGroup lateFillPropertyGroup(Asset anAsset, Class pg, long time) {
    return _prs.lateFillPropertyGroup(anAsset, pg, time);
  }

  class SecurePropertyProvider implements PropertyProvider {
    PropertyProvider _pp;
    ExecutionContext _ec;
    SecurePropertyProvider(PropertyProvider pp, ExecutionContext ec) {
      _pp = pp; 
      _ec = ec;
    }
    // PropertyProvider interface
    public void fillProperties(Asset anAsset) {
      _scs.setExecutionContext(_ec);
      _pp.fillProperties(anAsset);
      _scs.resetExecutionContext();
    }
    // GenericStateModel interface
    public int getModelState() {
       return _pp.getModelState();
    }
    public void initialize()
                throws StateModelException {
      _pp.initialize();
    }
    public void load()
          throws StateModelException {
      _pp.load();
    }
    public void start()
           throws StateModelException {
      _pp.start();
    }
    public void suspend()
             throws StateModelException {
      _pp.suspend();
    }
    public void resume()
            throws StateModelException {
      _pp.resume();
    }
    public void stop()
          throws StateModelException {
      _pp.stop();
    }
    public void halt()
          throws StateModelException {
      _pp.halt();
    }
    public void unload()
            throws StateModelException {
      _pp.unload();          
    }
  }// end class SecurePropertyProvider

  class SecureLatePropertyProvider implements LatePropertyProvider {
    LatePropertyProvider _lpp;
    ExecutionContext _ec;
    SecureLatePropertyProvider(LatePropertyProvider lpp, ExecutionContext ec) {
      _lpp = lpp; 
      _ec = ec;
    }
    // LatePropertyProvider interface
    public PropertyGroup fillPropertyGroup(Asset anAsset, Class pg, long time) {
      PropertyGroup retval = null;
      _scs.setExecutionContext(_ec);
      retval = _lpp.fillPropertyGroup(anAsset, pg, time);
      _scs.resetExecutionContext();
      return retval;
    }
    public Collection getPropertyGroupsProvided() {
      return _lpp.getPropertyGroupsProvided();
    }
    // GenericStateModel interface
    public int getModelState() {
       return _lpp.getModelState();
    }
    public void initialize()
                throws StateModelException {
      _lpp.initialize();
    }
    public void load()
          throws StateModelException {
      _lpp.load();
    }
    public void start()
           throws StateModelException {
      _lpp.start();
    }
    public void suspend()
             throws StateModelException {
      _lpp.suspend();
    }
    public void resume()
            throws StateModelException {
      _lpp.resume();
    }
    public void stop()
          throws StateModelException {
      _lpp.stop();
    }
    public void halt()
          throws StateModelException {
      _lpp.halt();
    }
    public void unload()
            throws StateModelException {
      _lpp.unload();          
    }
  }// end class SecureLatePropertyProvider
  
  class SecurePrototypeProvider implements PrototypeProvider {
    PrototypeProvider _pp;
    ExecutionContext _ec;
    SecurePrototypeProvider(PrototypeProvider pp, ExecutionContext ec) {
      _pp = pp; 
      _ec = ec;
    }
    // PrototypeProvider interface
    public Asset getPrototype(String aTypeName, Class anAssetClassHint) {
      Asset retval = null;
      _scs.setExecutionContext(_ec);
      retval = _pp.getPrototype(aTypeName, anAssetClassHint);
      _scs.resetExecutionContext();
      return retval;
    }
    // GenericStateModel interface
    public int getModelState() {
       return _pp.getModelState();
    }
    public void initialize()
                throws StateModelException {
      _pp.initialize();
    }
    public void load()
          throws StateModelException {
      _pp.load();
    }
    public void start()
           throws StateModelException {
      _pp.start();
    }
    public void suspend()
             throws StateModelException {
      _pp.suspend();
    }
    public void resume()
            throws StateModelException {
      _pp.resume();
    }
    public void stop()
          throws StateModelException {
      _pp.stop();
    }
    public void halt()
          throws StateModelException {
      _pp.halt();
    }
    public void unload()
            throws StateModelException {
      _pp.unload();          
    }
  }// end class SecurePrototypeProvider
}

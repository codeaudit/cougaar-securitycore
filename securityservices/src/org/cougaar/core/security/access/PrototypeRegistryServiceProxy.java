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
 
 
 
 
 
 
 
 


package org.cougaar.core.security.access;

import java.util.Collection;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.auth.ExecutionContext;
import org.cougaar.planning.ldm.LatePropertyProvider;
import org.cougaar.planning.ldm.PropertyProvider;
import org.cougaar.planning.ldm.PrototypeProvider;
import org.cougaar.planning.ldm.asset.Asset;
import org.cougaar.planning.ldm.asset.PropertyGroup;
import org.cougaar.planning.service.PrototypeRegistryService;
import org.cougaar.util.StateModelException;

// this class is a proxy for the PrototypeRegistryService
class PrototypeRegistryServiceProxy extends SecureServiceProxy 
  implements PrototypeRegistryService {
  private final PrototypeRegistryService _prs;
  //private final Object _requestor;
  
  public PrototypeRegistryServiceProxy(PrototypeRegistryService prs, Object requestor, ServiceBroker sb) {
    super(sb);
    _prs = prs;
    //_requestor = requestor;
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

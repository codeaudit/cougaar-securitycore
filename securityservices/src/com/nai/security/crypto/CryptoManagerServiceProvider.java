/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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
 * Created on September 12, 2001, 10:55 AM
 */

package com.nai.security.crypto;

import org.cougaar.core.component.ServiceProvider;
import org.cougaar.core.component.ServiceBroker;
import com.nai.security.access.AccessControlPolicyService;
import com.nai.security.access.AccessControlPolicyServiceImpl;

import java.security.Security;
import java.security.Provider;

public class CryptoManagerServiceProvider implements ServiceProvider {
    private static CryptoPolicyService cps = null;
    private static AccessControlPolicyService acps = null;

    /** Creates new CryptoManagerServiceProvider */
    public CryptoManagerServiceProvider() {
      // Load cryptographic providers
      CryptoProviders.loadCryptoProviders();

        KeyRing.getKeyStore();
	String debug = System.getProperty("org.cougaar.message.transport.debug");
        if ( debug!=null && (debug.equalsIgnoreCase("true") || debug.indexOf("security")>=0) ) {
            Provider[] plist=Security.getProviders();
            for(int i=0;i<plist.length;i++){
                System.out.println("["+(i+1)+"]:"+plist[i].getName());
            }
        }
        
      cps = new CryptoPolicyServiceImpl();
      acps = new AccessControlPolicyServiceImpl();
    }

    public Object getService(ServiceBroker sb, Object obj, Class cls) {
        if(cls==CryptoManagerService.class){
            return new CryptoManagerServiceImpl();
        }else if(cls==CryptoPolicyService.class){
            if( cps==null ) cps = new CryptoPolicyServiceImpl();
            return cps;
        }else if(cls==AccessControlPolicyService.class){
            if( acps==null ) acps = new AccessControlPolicyServiceImpl();
            return acps;
        }else{
            return null;
        }
    }
    
    public void releaseService(ServiceBroker sb, Object obj1, Class cls, Object obj2) {
    }
    
}

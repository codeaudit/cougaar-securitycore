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

package org.cougaar.core.security.crypto.crl.plugin;


import java.util.*;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.CRLException;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.*;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.multicast.AttributeBasedAddress;

import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.util.StateModelException ;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.util.UID;
import org.cougaar.core.service.community.*;


import org.cougaar.core.security.crypto.crl.blackboard.*;
import org.cougaar.core.security.crypto.CertDirectoryServiceRequestorImpl;
import org.cougaar.core.security.crypto.CRLWrapper;
import org.cougaar.core.security.crypto.CertificateUtility;
import org.cougaar.core.security.naming.CACertificateEntry;

import org.cougaar.core.security.services.crypto.*;
import org.cougaar.core.security.services.ldap.CertDirectoryServiceClient;
import org.cougaar.core.security.services.ldap.CertDirectoryServiceRequestor;
import org.cougaar.core.security.util.DateUtil;
import org.cougaar.core.security.services.util.CertificateSearchService;


public class CrlAgentRegistrationPlugin extends ComponentPlugin {

  // The domainService acts as a provider of domain factory services
  private DomainService domainService = null;
  private IncrementalSubscription crlagentregistration;
  private IncrementalSubscription crlregistrationtable;
  private LoggingService loggingService=null;
  private CrlRegistrationTable crlRegistrationTable=null;
  //private boolean completeregistration =true;

  /** The number of seconds between crl updates */
  protected long    _pollInterval    = 60000l;
  
  class CRLAgentRegistrationPredicate implements UnaryPredicate{
    public boolean execute(Object o) {
      //loggingService.debug(" Object on BB is :"+ o.toString());
      boolean ret = false;
      if (o instanceof  CrlRelay ) {
	return true;
      }
      return ret;
    }
  }
  class CRLRegistrationTablePredicate implements UnaryPredicate{
    public boolean execute(Object o) {
      boolean ret = false;
      if (o instanceof  CrlRegistrationTable ) {
	return true;
      }
      return ret;
    }
  }

  /**
   * Used by the binding utility through reflection to set my DomainService
   */
  public void setDomainService(DomainService aDomainService) {
    domainService = aDomainService;
  }

  /**
   * Used by the binding utility through reflection to get my DomainService
   */
  public DomainService getDomainService() {
    return domainService;
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
    
    String paramName = "CRL Provider poll interval";
    Iterator iter = l.iterator();
    String param = new String();
    try {
      param = iter.next().toString();
      _pollInterval = (Integer.parseInt(param.trim()))*1000l;
    }
    catch (NoSuchElementException e) {
      throw new IllegalArgumentException("You must provide a " +
                                         paramName +
                                         " argument");
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException("Expecting integer for " +
                                         paramName +
                                         ". Got (" +
                                         param + ")");
    }
   
  }

  protected void setupSubscriptions() {

    loggingService = (LoggingService)getBindingSite().getServiceBroker().getService
      (this, LoggingService.class, null);

    loggingService.debug("Set up subscription of CRL Agent Registration Plugin  called :");
    if(getBlackboardService().didRehydrate()) {
      Collection regcollection =getBlackboardService().query(new CRLRegistrationTablePredicate());
      if(regcollection.isEmpty()){
	loggingService.debug(" Reg table collection size:"+ regcollection.size());
	loggingService.error(" BlackBoard Rehydrated but there is no crl registration:");
	return;
      }
      else {
        Iterator iter=regcollection.iterator();
        if(iter.hasNext()) {
          crlRegistrationTable=(CrlRegistrationTable)iter.next();
        }

      }
    }
    else {
      crlRegistrationTable=new CrlRegistrationTable();
      getBlackboardService().publishAdd(crlRegistrationTable);
      loggingService.debug(" Publishing CRL reg table :");
    }
    crlagentregistration=(IncrementalSubscription)getBlackboardService().subscribe
      (new CRLAgentRegistrationPredicate());

    loggingService.debug("CRL Provider Poll time set to:"+(_pollInterval/1000));
    
    /* Thread td=new Thread(new CRLUpdate(),"CRL-Agent Reg thread");
       td.start();
    */
    ThreadService ts = (ThreadService) getServiceBroker().
      getService(this, ThreadService.class, null);
    ts.schedule(new CRLUpdate(), 0, _pollInterval );
    loggingService.debug("Set up subscription done:"); 

  }

  protected void execute () {
    Iterator regiterator=null;
    Iterator regTableiterator=null;
    CrlRegistrationObject regobject=null;
    CrlRelay crlrelay=null;
    CRLAgentRegistration regagentObject=null;
    Collection regcollection= crlagentregistration.getAddedCollection();
    //Collection completecollection= crlagentregistration.getCollection();
    //loggingService.debug("execute of crl agent registration plugin called ");
    loggingService.debug("execute of crl agent registration plugin called "+crlagentregistration.hasChanged());
    loggingService.debug("Recived Collection size for new CRL Registration :"+regcollection.size());
    //loggingService.debug("Complete Collection size for CRL Registration :"+completecollection.size());
    boolean modified=false;
    if(crlRegistrationTable==null) {
      // completeregistration=false;
      loggingService.error("CRL registration table is null ");
      return;
    }
    loggingService.debug("CRL agent registration data received:"+regcollection.size());
    regiterator=regcollection.iterator();
    while(regiterator.hasNext()) {
      // loggingService.debug("In while of reg iterator :");
      crlrelay=(CrlRelay)regiterator.next();
      regagentObject=(CRLAgentRegistration)crlrelay.getContent();
      loggingService.debug("CRL agent registration data received:"+regagentObject.dnName +"::"
			   +crlrelay.getSource());
      //Vector listMessageAddress=null;
      synchronized(crlRegistrationTable) {
        if(crlRegistrationTable.containsKey(regagentObject.dnName)) {
          loggingService.debug("reg table contains key "+ regagentObject.toString());
          regobject=(CrlRegistrationObject)crlRegistrationTable.get(regagentObject.dnName);
          try {
            loggingService.debug("Adding Agent :" + crlrelay.getSource() +"for Dn:"+regagentObject.dnName);
            regobject.addAgent(crlrelay.getSource());
          }
          catch (CRLAgentRegistrationException crlagentexp) {
            loggingService.debug(" Agent has alredy been registered :"+crlrelay.getSource() );
          }
          byte[] encodedcrl= null;
          try{
            if((regobject.getCRL()!=null)&&(regobject.getModifiedTimeStamp()!=null)){
              encodedcrl= regobject.getCRL().getEncoded();
            }
          }
          catch(java.security.cert.CRLException crlexp) {
            loggingService.error("Unable to encode crl :" + crlexp.getMessage());
          }
          if(regobject.getModifiedTimeStamp()!=null) {
            crlrelay.updateResponse(crlrelay.getSource(),
                                    new CRLWrapper(regobject.dnName,encodedcrl,regobject.getModifiedTimeStamp()));
            getBlackboardService().publishChange(crlrelay);
            loggingService.debug("Updating response after first time registration :"+crlrelay.getSource().toString()); 
          }
	
          modified=true;
        }
        else {
          loggingService.debug("Adding agent to CRL registration table :"+regagentObject.toString() +"::"
                               +crlrelay.getSource());
          regobject=new CrlRegistrationObject(regagentObject.dnName);
          try {
            regobject.addAgent(crlrelay.getSource());
          }
          catch(CRLAgentRegistrationException crlagentexp){
            loggingService.debug(" Agent has alredy been registered :"+crlrelay.getSource());
          }
          modified=true;
          loggingService.debug("Agent is being registered :"+regagentObject.dnName +"::"
                               +crlrelay.getSource());
          //regtable.put(regagentObject.dnName,regobject);
        }
        if(modified){
          crlRegistrationTable.put(regagentObject.dnName,regobject);
        }
      }// end of  synchronized(crlRegistrationTable)
    } // end of  while(regiterator.hasNext()
    //loggingService.debug("Going to Publishing  Crl registration table :");
    if(modified){
      loggingService.debug("Publishing Crl registration table :");
      getBlackboardService().publishChange(crlRegistrationTable);
    }
  }

  private class CRLUpdate extends TimerTask {

    public CRLUpdate () {
    }

    public void run() {
      Date time = new Date(System.currentTimeMillis());
      loggingService.debug("CRL agent registartion Thread  has started : "+time.toString());
      BlackboardService bbs = getBlackboardService();
      
      Collection regCollection=null;
      CertificateSearchService searchService=(CertificateSearchService)getBindingSite().getServiceBroker()
        .getService(this, CertificateSearchService.class, null);
      if(searchService==null) {
        loggingService.warn(" Unable to get CRL as Search Service is NULL:");
        return;
      }
     
      String key=null;
      boolean modified=false;
      bbs.openTransaction();
      int counter=0;
      synchronized(crlRegistrationTable){
        Set regset=crlRegistrationTable.keySet();
        Iterator keyiterator=regset.iterator();
        CrlRegistrationObject regObject=null;
        while(keyiterator.hasNext()) {
          key=(String)keyiterator.next();
          regObject =(CrlRegistrationObject)crlRegistrationTable.get(key);
          loggingService.debug(" Registration Object in CRL registration Table is :"+ regObject.toString());
          String modifiedTimestamp=null;
          X509CRL crl=null;
          List certList=searchService.findCert(CertificateUtility.getX500Name(regObject.dnName));
          if(certList.size()>0) {
            loggingService.debug(" List size returned after search for :"+regObject.dnName +
                                 " size-"+certList.size());
            Iterator certEntryIterator=certList.iterator();
            Object certEntryObject=null;
            CACertificateEntry caCertEntry=null;
            byte[] encodedCRL=null;
            while(certEntryIterator.hasNext()) {
              certEntryObject=certEntryIterator.next();
              if(certEntryObject instanceof CACertificateEntry) {
                caCertEntry=(CACertificateEntry)certEntryObject;
                encodedCRL=caCertEntry.getEncodedCRL();
                loggingService.debug("Getting the modified time stamp for :"+ regObject.dnName);
                modifiedTimestamp=caCertEntry.getLastModifiedTimeStamp();
                loggingService.debug("Modified time stamp for :"+ regObject.dnName);
                if(regObject.getModifiedTimeStamp()!=null) { 
                  loggingService.debug("Reg object modified stamp was NOT null");
                  Date lastmodified=DateUtil.getDateFromUTC(regObject.getModifiedTimeStamp());
                  Date currentLastmodified=DateUtil.getDateFromUTC(modifiedTimestamp);
                  loggingService.debug("Modified time stamp in CRL registration table :"+regObject.getModifiedTimeStamp()
                                       + "date format :"+lastmodified.toString() );
                  loggingService.debug("Modified time stamp in Ldap  :"+modifiedTimestamp
                                       + "date format :"+currentLastmodified.toString() );
                  if(currentLastmodified.after(lastmodified)){
                    loggingService.debug("Ldap entry has been modified:");
                    regObject.setModifiedTime(modifiedTimestamp);
                    if(encodedCRL!=null) {
                      regObject.setCRL(encodedCRL);
                      modified=true;

                    }// end of if(encodedCRL!=null) 
                    else {
                      loggingService.error("Unable to get CRL for DN:"+regObject.dnName); 
                    }
                  
                  }//end if(currentLastmodified.after(lastmodified))
                 
                }// end of if(regObject.getModifiedTimeStamp()!=null)
                else {
                  loggingService.debug("Reg object modified stamp was null setting it to  :"+modifiedTimestamp);
                  if(encodedCRL!=null) {
                    regObject.setModifiedTime(modifiedTimestamp);
                    regObject.setCRL(encodedCRL);
                    modified=true;
                  
                  }// end of if(encodedCRL!=null) 
                  else {
                    loggingService.error("Unable to get CRL for DN:"+regObject.dnName); 
                  }
                }
                if(modified) {
                  Vector messageAddress=regObject.getRegisteredAgents();
                  CrlRelay crlrelay=null;
                  for(int i=0;i<messageAddress.size();i++){
                    MessageAddress agent=(MessageAddress)messageAddress.elementAt(i);
                    crlrelay=getAgentrelay(agent,regObject.dnName);
                    if(crlrelay!=null) {
                      try{
                        crlrelay.updateResponse(crlrelay.getSource(),
                                                new CRLWrapper(regObject.dnName,encodedCRL,modifiedTimestamp));
                        bbs.publishChange(crlrelay);
                        loggingService.debug("Updating response  :"+agent.toString());
                        loggingService.debug("Updating response  :"+crlrelay.toString());
                      }
                      catch(Exception exp) {
                        loggingService.warn("Unable to send updated CRL to agent :"+agent.toString()+ exp.getMessage());
                      }
                    }
                    else {
                      loggingService.warn("Unable to send updated CRL to agent :"+agent.toString());
                    }
                  }//end of For loop
                
                  crlRegistrationTable.put(regObject.dnName,regObject);
                  bbs.publishChange(crlRegistrationTable);
                  loggingService.debug("published crl reg table after modifying timestamp or crl ");
                }//end if (modified)
              }//end if(certEntryObject instanceof CACertifcteEntry)
              else {
                loggingService.warn("List returned by search service contaians object"+
                                    "of type other than CA Cert Entry :"+ regObject.dnName);
                loggingService.warn("received object in search list is :"+
                                    certEntryObject.getClass().getName());
              }
            }//end of  while(certEntryIterator.hasNext()) 
          
          }// end of if(certList.size()>0)
          else {
            loggingService.warn(" unable to get Certifificate entry for DN :"+ regObject.dnName);
          
          }
        }//end of  while(keyiterator.hasNext())
      }//end of synchronized(crlRegistrationTable)
      bbs.closeTransaction();
      loggingService.debug("CRL agent registartion Thread  has finished:");

    }
     

    /*
      This is the old implementation which would poll the Ldap for crl
      CertDirectoryServiceClient directoryclient=getDirectoryService(regObject.dnName,
      regObject.ldapUrl,
      regObject.ldapType);
      String modifiedTimestamp=null;
      X509CRL crl=null;
      if(directoryclient!=null) {
      crl=directoryclient.getCRL(regObject.dnName);
      loggingService.debug("Getting the modified time stamp for :"+ regObject.dnName);
      modifiedTimestamp=directoryclient.getModifiedTimeStamp(regObject.dnName);
      loggingService.debug("Modified time stamp for :"+ regObject.dnName);
      if(regObject.getModifiedTimeStamp()!=null) {
      loggingService.debug("Reg object modified stamp was NOT null");
      Date lastmodified=DateUtil.getDateFromUTC(regObject.getModifiedTimeStamp());
      Date currentLastmodified=DateUtil.getDateFromUTC(modifiedTimestamp);
      loggingService.debug("Modified time stamp in CRL registration table :"+regObject.getModifiedTimeStamp()
      + "date format :"+lastmodified.toString() );
      loggingService.debug("Modified time stamp in Ldap  :"+modifiedTimestamp
      + "date format :"+currentLastmodified.toString() );
      if(currentLastmodified.after(lastmodified)){
      loggingService.debug("Ldap entry has been modified:");
      regObject.setModifiedTime(modifiedTimestamp);
      try {
      regObject.setCRL(crl.getEncoded());
      }
      catch(CRLException crlexp) {
      loggingService.error(" Unable to encode CRL "+ crlexp.getMessage());
      }
      modified=true;
      }//end if(currentLastmodified.after(lastmodified))

      }
      else {
      loggingService.debug("Reg object modified stamp was null setting it to  :"+modifiedTimestamp);
      try {
      regObject.setCRL(crl.getEncoded());
      }
      catch(CRLException crlexp) {
      loggingService.error(" Unable to encode CRL "+ crlexp.getMessage());
      }
      regObject.setModifiedTime(modifiedTimestamp);
      modified=true;
      }//end else of regObject.getModifiedTimeStamp()!=null
      }//end of if(directoryclient!=null)
      if(modified) {
      Vector messageAddress=regObject.getRegisteredAgents();
      CrlRelay crlrelay=null;
      for(int i=0;i<messageAddress.size();i++){
      MessageAddress agent=(MessageAddress)messageAddress.elementAt(i);
      crlrelay=getAgentrelay(agent,regObject.dnName);
      if(crlrelay!=null) {
      try{
      crlrelay.updateResponse(crlrelay.getSource(),
      new CRLWrapper(regObject.dnName,crl.getEncoded(),modifiedTimestamp));
      bbs.publishChange(crlrelay);
      loggingService.debug("Updating response  :"+agent.toString());
      loggingService.debug("Updating response  :"+crlrelay.toString());
      }
      catch(Exception exp) {
      loggingService.warn("Unable to send updated CRL to agent :"+agent.toString()+ exp.getMessage());
      }
      }
      else {
      loggingService.warn("Unable to send updated CRL to agent :"+agent.toString());
      }
      }//end of For loop
      regtable.put(regObject.dnName,regObject);
      bbs.publishChange(crlRegistrationTable);
      loggingService.debug("published crl reg table after modifying timestamp or crl ");
      }//end if (modified)
      }//end of while
      bbs.closeTransaction();
      loggingService.debug("CRL agent registartion Thread  has finished:");

      }
    */


    private void dump(X509CRL currentcrl, X509CRL oldcrl) {
      Set currentset=null;
      Set oldset=null;
      if(currentcrl!=null) {
	loggingService.debug("currentcrl is not null:");
	currentset=currentcrl.getRevokedCertificates();
	if( currentset!=null) {
	  loggingService.debug("current set size is :"+currentset.size());
	}
	else {
	  loggingService.debug("currentcrl set is null :");
	}

      }
      if(oldcrl!=null) {
	loggingService.debug("old crl is not null:");
	oldset=oldcrl.getRevokedCertificates();
	if(oldset!=null) {
	  loggingService.debug("set size is :"+oldset.size());
	}
	else {
	  loggingService.debug("oldset crl  is null :");
	}
      }
      else {
	loggingService.debug("oldset crl  is null :");
      }
      loggingService.debug("Logging current as well as old crl set  :");
      dumpX509CRL(currentset,oldset);
    }

    private CrlRelay getAgentrelay(MessageAddress agent, String dn){
      BlackboardService bbs = getBlackboardService();
      Collection regrelayCollection=null;
      CrlRelay crlrelay=null;
      CRLAgentRegistration agentReg=null;
      regrelayCollection=bbs.query(new CRLAgentRegistrationPredicate ());
      Iterator iter=regrelayCollection.iterator();
      while(iter.hasNext()) {
	crlrelay=(CrlRelay)iter.next();
	if(crlrelay.getSource().equals(agent)){
	  agentReg=(CRLAgentRegistration)crlrelay.getContent();
	  if(agentReg.dnName.equals(dn)) {
      	    return crlrelay;
	  }
	}
        crlrelay=null;
      }
      return crlrelay;
    }

    private CertDirectoryServiceClient getDirectoryService(String dnname,String ldapURL,int ldapType) {
      // TODO: this should not use the ldap dependent classes anymore here
      CertDirectoryServiceRequestor cdsr =
	new CertDirectoryServiceRequestorImpl(ldapURL,ldapType,
                                              (String)null,(String)null,
					      getBindingSite().getServiceBroker());
      CertDirectoryServiceClient cf = (CertDirectoryServiceClient)
	getBindingSite().getServiceBroker().getService(cdsr, CertDirectoryServiceClient.class, null);
      return cf;
    }
  }

  private boolean compareCRL(X509CRL currentcrl, X509CRL oldcrl) {
    boolean equal=false;
    if(oldcrl==null) {
      loggingService.debug("Crl are not equal as old crl is null ");
      return false;
    }
    if(currentcrl==null) {
      loggingService.debug("Crl are not equal as current  crl is null ");
      return false;
    }
    Set currentset=currentcrl.getRevokedCertificates();
    Set oldset=oldcrl.getRevokedCertificates();
    if((currentset!=null)&&(oldset!=null)){
      if(currentset.size()>oldset.size()) {
	dumpX509CRL(currentset,oldset);
	equal=false;
      }
      else{
	loggingService.debug("Size are equal for old as well as new crl :"+ "old:"+oldset.size()+
			     "new crl size"+ currentset.size());
	equal=true;
      }
    }
    return equal;

  }

  private void dumpX509CRL(Set current,Set old) {
    loggingService.debug(" Current crl set is :");
    X509CRLEntry crlentry=null;
    if(current!=null) {
      Iterator iter=current.iterator();

      while(iter.hasNext()){
	crlentry=(X509CRLEntry)iter.next();
	if(crlentry!=null) {
	  loggingService.debug(" crl entry is  :"+crlentry.toString());
	}
      }
    }
    loggingService.debug(" Old crl set is :");
    if(old!=null) {
      Iterator iter=old.iterator();
      while(iter.hasNext()){
	crlentry=(X509CRLEntry)iter.next();
	if(crlentry!=null) {
	  loggingService.debug(" crl entry is  :"+crlentry.toString());
	}
      }
    }
  }

  
 

}

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


package org.cougaar.core.security.crypto.crl.plugin;


import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.Vector;

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.crypto.CRLWrapper;
import org.cougaar.core.security.crypto.CertDirectoryServiceRequestorImpl;
import org.cougaar.core.security.crypto.CertificateUtility;
import org.cougaar.core.security.crypto.crl.blackboard.CRLAgentRegistration;
import org.cougaar.core.security.crypto.crl.blackboard.CRLAgentRegistrationException;
import org.cougaar.core.security.crypto.crl.blackboard.CrlRegistrationObject;
import org.cougaar.core.security.crypto.crl.blackboard.CrlRegistrationTable;
import org.cougaar.core.security.crypto.crl.blackboard.CrlRelay;
import org.cougaar.core.security.naming.CACertificateEntry;
import org.cougaar.core.security.services.ldap.CertDirectoryServiceClient;
import org.cougaar.core.security.services.ldap.CertDirectoryServiceRequestor;
import org.cougaar.core.security.services.util.CertificateSearchService;
import org.cougaar.core.security.util.DateUtil;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.EventService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.thread.Schedulable;
import org.cougaar.util.UnaryPredicate;


public class CrlAgentRegistrationPlugin extends ComponentPlugin {

  // The domainService acts as a provider of domain factory services
  private DomainService domainService = null;
  private IncrementalSubscription crlagentregistration;
  private LoggingService loggingService=null;
  private EventService eventService=null;
  private CrlRegistrationTable crlRegistrationTable=null;
  private Schedulable crlPollingThread=null;
  //private boolean completeregistration =true;

  /** The number of seconds between crl updates */
  protected long    _pollInterval    = 60 * 1000L;
  

  /** The age after which we should put a warning in log4j if
   * we have not been able to find a certificate.
   */
  private long WARNING_IF_DN_NOT_FOUND = 5 * 60 * 1000L;

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

  public void setEventService(EventService service) {
    eventService = service;
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
    if(loggingService.isDebugEnabled()){
      loggingService.debug("Set up subscription of CRL Agent Registration Plugin  called :");
    }
    if(getBlackboardService().didRehydrate()) {
      Collection regcollection =getBlackboardService().query(new CRLRegistrationTablePredicate());
      if(regcollection.isEmpty()){
        if(loggingService.isDebugEnabled()){
          loggingService.debug(" Reg table collection size:"+ regcollection.size());
        }
        if(loggingService.isErrorEnabled()){
          loggingService.error(" BlackBoard Rehydrated but there is no crl registration:");
        }
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
      if(loggingService.isDebugEnabled()){
        loggingService.debug(" Publishing CRL reg table :");
      }
    }
    crlagentregistration=(IncrementalSubscription)getBlackboardService().subscribe
      (new CRLAgentRegistrationPredicate());
    if(loggingService.isDebugEnabled()){
      loggingService.debug("CRL Provider Poll time set to:"+(_pollInterval/1000));
    }
    
    /* Thread td=new Thread(new CRLUpdate(),"CRL-Agent Reg thread");
       td.start();
    */
    ThreadService ts = (ThreadService) getServiceBroker().
      getService(this, ThreadService.class, null);
    crlPollingThread=ts.getThread(this, new CRLUpdate());
    crlPollingThread.schedule(0, _pollInterval );
    if(loggingService.isDebugEnabled()){
      loggingService.debug("Set up subscription done:"); 
    }
  }

  protected void execute () {
    Iterator regiterator=null;
    CrlRegistrationObject regobject=null;
    CrlRelay crlrelay=null;
    CRLAgentRegistration regagentObject=null;
    Collection regcollection= crlagentregistration.getAddedCollection();
    //Collection completecollection= crlagentregistration.getCollection();
    //loggingService.debug("execute of crl agent registration plugin called ");
    if(loggingService.isDebugEnabled()){
      loggingService.debug("execute of crl agent registration plugin called "+crlagentregistration.hasChanged());
      loggingService.debug("Recived Collection size for new CRL Registration :"+regcollection.size());
    }
    //loggingService.debug("Complete Collection size for CRL Registration :"+completecollection.size());
    boolean modified=false;
    if(crlRegistrationTable==null) {
      // completeregistration=false;
      if(loggingService.isErrorEnabled()){
        loggingService.error("CRL registration table is null ");
      }
      return;
    }
    if(loggingService.isDebugEnabled()){
      loggingService.debug("CRL agent registration data received:"+regcollection.size());
    }
    regiterator=regcollection.iterator();
    while(regiterator.hasNext()) {
      // loggingService.debug("In while of reg iterator :");
      crlrelay=(CrlRelay)regiterator.next();
      regagentObject=(CRLAgentRegistration)crlrelay.getContent();
      if(loggingService.isDebugEnabled()){
        loggingService.debug("CRL agent registration data received:"+regagentObject.dnName +"::"
                             +crlrelay.getSource());
      }
      //Vector listMessageAddress=null;
      synchronized(crlRegistrationTable) {
        if(crlRegistrationTable.containsKey(regagentObject.dnName)) {
          if(loggingService.isDebugEnabled()){
            loggingService.debug("reg table contains key "+ regagentObject.toString());
          }
          regobject=(CrlRegistrationObject)crlRegistrationTable.get(regagentObject.dnName);
          if(regagentObject.toRegister()){
            try {
              loggingService.debug("Adding Agent :" + crlrelay.getSource() +"for Dn:"+regagentObject.dnName);
              regobject.addAgent(crlrelay.getSource());
              event("CrlRegistration", crlrelay.getSource(), regagentObject.dnName);
            }
            catch (CRLAgentRegistrationException crlagentexp) {
              if(loggingService.isDebugEnabled()){
                loggingService.debug(" Agent has alredy been registered :"+crlrelay.getSource() );
              }
            }
            byte[] encodedcrl= null;
            try{
              if((regobject.getCRL()!=null)&&(regobject.getModifiedTimeStamp()!=null)){
                encodedcrl= regobject.getCRL().getEncoded();
              }
            }
            catch(java.security.cert.CRLException crlexp) {
              if(loggingService.isErrorEnabled()){
                loggingService.error("Unable to encode crl :" + crlexp.getMessage());
              }
            }
            if(regobject.getModifiedTimeStamp()!=null) {
              crlrelay.updateResponse(crlrelay.getSource(),
                                      new CRLWrapper(regobject.dnName,encodedcrl,regobject.getModifiedTimeStamp()));
              getBlackboardService().publishChange(crlrelay);
              if(loggingService.isDebugEnabled()){
                loggingService.debug("Updating response after first time registration :"+crlrelay.getSource().toString()); 
              }
            }
            modified=true;
          }
          else {
            try {
              if(loggingService.isDebugEnabled()){
                loggingService.debug("Removing  Agent :" + crlrelay.getSource() +"for Dn:"+regagentObject.dnName);
              }
              regobject.removeAgent(crlrelay.getSource().toString());
              event("CrlUNRegistration", crlrelay.getSource(), regagentObject.dnName);
            }
            catch (CRLAgentRegistrationException crlagentexp) {
              if(loggingService.isDebugEnabled()){
                loggingService.debug(" Agent has alredy been registered :"+crlrelay.getSource() );
              }
            }
            modified=true;
          }
        }
        else {
          if(loggingService.isDebugEnabled()){
            loggingService.debug("Adding agent to CRL registration table :"+regagentObject.toString() +"::"
                                 +crlrelay.getSource());
          }
          regobject=new CrlRegistrationObject(regagentObject.dnName);
          try {
            regobject.addAgent(crlrelay.getSource());
            event("CrlRegistration", crlrelay.getSource(), regagentObject.dnName);
          }
          catch(CRLAgentRegistrationException crlagentexp){
            if(loggingService.isDebugEnabled()){
              loggingService.debug(" Agent has alredy been registered :"+crlrelay.getSource());
            }
          }
          modified=true;
          if(loggingService.isDebugEnabled()){
            loggingService.debug("Agent is being registered :"+regagentObject.dnName +"::"
                                 +crlrelay.getSource());
          }
          //regtable.put(regagentObject.dnName,regobject);
        }
        if(modified){
          crlRegistrationTable.put(regagentObject.dnName,regobject);
        }
      }// end of  synchronized(crlRegistrationTable)
    } // end of  while(regiterator.hasNext()
    //loggingService.debug("Going to Publishing  Crl registration table :");
    if(modified){
      if(loggingService.isDebugEnabled()){
        loggingService.debug("Publishing Crl registration table :");
      }
      getBlackboardService().publishChange(crlRegistrationTable);
    }
  }
  public void unload() {
    if(crlPollingThread!=null) {
      crlPollingThread.cancel();
    }
  }

  private class CRLUpdate implements Runnable {

    /**
     * A list of DN names for which we could not find a certificate
     * We need to give some time before the society starts, but
     * after a while we should print a warning if we could not find
     * the certificate.
     * A map from DN names (String) to date of first entry (Date)
     */
    private Map _namesNotFound = new HashMap();

    public CRLUpdate () {
    }

    public void run() {
      Date time = new Date(System.currentTimeMillis());
      if(loggingService.isDebugEnabled()){
        loggingService.debug("CRL agent registartion Thread  has started : "+time.toString());
      }
      BlackboardService bbs = getBlackboardService();
      
      CertificateSearchService searchService=(CertificateSearchService)getBindingSite().getServiceBroker()
        .getService(this, CertificateSearchService.class, null);
      if(searchService==null) {
        if(loggingService.isDebugEnabled()){
          loggingService.warn("Unable to get CRL as Search Service is NULL:");
        }
        return;
      }
      if(loggingService.isDebugEnabled()){
        loggingService.debug(" Starting the polling in CRL Registration plugin for CRLs");
      }
     
      String key=null;
      boolean modified=false;
      bbs.openTransaction();
      synchronized(crlRegistrationTable){
        Set regset=crlRegistrationTable.keySet();
        Iterator keyiterator=regset.iterator();
        CrlRegistrationObject regObject=null;
        while(keyiterator.hasNext()) {
          key=(String)keyiterator.next();
          regObject =(CrlRegistrationObject)crlRegistrationTable.get(key);
          if(loggingService.isDebugEnabled()){
            loggingService.debug(" Registration Object in CRL registration Table is :"+ regObject.toString());
          }
          String modifiedTimestamp=null;
          List certList=searchService.findCert(CertificateUtility.getX500Name(regObject.dnName));
          if(certList.size()>0) {
            if(loggingService.isDebugEnabled()){
              loggingService.debug(" List size returned after search for :"+regObject.dnName +
                                   " size-"+certList.size());
            }
            Iterator certEntryIterator=certList.iterator();
            Object certEntryObject=null;
            CACertificateEntry caCertEntry=null;
            byte[] encodedCRL=null;
            while(certEntryIterator.hasNext()) {
              certEntryObject=certEntryIterator.next();
              if(certEntryObject instanceof CACertificateEntry) {
                caCertEntry=(CACertificateEntry)certEntryObject;
                encodedCRL=caCertEntry.getEncodedCRL();
                if(loggingService.isDebugEnabled()){
                  loggingService.debug("Getting the modified time stamp for :"+ regObject.dnName);
                }
                modifiedTimestamp=caCertEntry.getLastModifiedTimeStamp();
                if(loggingService.isDebugEnabled()) {
                  loggingService.debug(" Received modified Time stamp from Naming Entry is :"+modifiedTimestamp); 
                  loggingService.debug("Modified time stamp for :"+ regObject.dnName);
                }
                if(regObject.getModifiedTimeStamp()!=null) { 
                  loggingService.debug("Reg object modified stamp was NOT null");
                  Date lastmodified=DateUtil.getDateFromUTC(regObject.getModifiedTimeStamp());
                  Date currentLastmodified=DateUtil.getDateFromUTC(modifiedTimestamp);
                  if(loggingService.isDebugEnabled()){
                    loggingService.debug("Modified time stamp in CRL registration table :"+regObject.getModifiedTimeStamp()
                                         + "date format :"+lastmodified.toString() );
                    loggingService.debug("Modified time stamp in Ldap  :"+modifiedTimestamp
                                         + "date format :"+currentLastmodified.toString() );
                  }
                  if(currentLastmodified.after(lastmodified)){
                    if(loggingService.isDebugEnabled()){
                      loggingService.debug("Ldap entry has been modified:");
                    }
                    regObject.setModifiedTime(modifiedTimestamp);
                    if(encodedCRL!=null) {
                      regObject.setCRL(encodedCRL);
                      modified=true;

                    }// end of if(encodedCRL!=null) 
                    else {
                      if(loggingService.isDebugEnabled()){
                        loggingService.error("Unable to get CRL for DN:"+regObject.dnName); 
                      }
                    }
                  
                  }//end if(currentLastmodified.after(lastmodified))
                 
                }// end of if(regObject.getModifiedTimeStamp()!=null)
                else {
                  if(loggingService.isDebugEnabled()){
                    loggingService.debug("Reg object modified stamp was null setting it to  :"+modifiedTimestamp);
                  }
                  if(encodedCRL!=null) {
                    regObject.setModifiedTime(modifiedTimestamp);
                    regObject.setCRL(encodedCRL);
                    modified=true;
                  
                  }// end of if(encodedCRL!=null) 
                  else {
                    if(loggingService.isErrorEnabled()){
                      loggingService.error("Unable to get CRL for DN:"+regObject.dnName); 
                    }
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
                        if(loggingService.isDebugEnabled()){
                          loggingService.debug("Updating response  :"+agent.toString());
                          loggingService.debug("Updating response  :"+crlrelay.toString());
                        }

                        event("updateCRL", agent, regObject.dnName);
                      }
                      catch(Exception exp) {
                        if(loggingService.isWarnEnabled()){
                          loggingService.warn("Unable to send updated CRL to agent :"+agent.toString()+ exp.getMessage());
                        }
                      }
                    }
                    else {
                      if(loggingService.isWarnEnabled()){
                        loggingService.warn("Unable to send updated CRL to agent :"+agent.toString());
                      }
                    }
                  }//end of For loop
                
                  crlRegistrationTable.put(regObject.dnName,regObject);
                  bbs.publishChange(crlRegistrationTable);
                  if(loggingService.isWarnEnabled()){
                    loggingService.debug("published crl reg table after modifying timestamp or crl ");
                  }
                }//end if (modified)
              }//end if(certEntryObject instanceof CACertifcteEntry)
              else {
                if(loggingService.isWarnEnabled()){
                  loggingService.warn("List returned by search service contains object"+
                                      "of type other than CA Cert Entry :"+ regObject.dnName);
                  loggingService.warn("received object in search list is :"+
                                      certEntryObject.getClass().getName());
                }
              }
            }//end of  while(certEntryIterator.hasNext()) 

            // Name was found, so remove it.
            _namesNotFound.remove(regObject.dnName);
          }// end of if(certList.size()>0)
          else {
            if (!_namesNotFound.containsKey(regObject.dnName)) {
              _namesNotFound.put(regObject.dnName, new Date(System.currentTimeMillis()));
            }
            if (loggingService.isInfoEnabled()) {
              loggingService.info("Unable to get Certifificate entry for DN :"+ regObject.dnName);
            }
          }
        }//end of  while(keyiterator.hasNext())
      }//end of synchronized(crlRegistrationTable)
      bbs.closeTransaction();
      if(loggingService.isDebugEnabled()){
        loggingService.debug("CRL agent registartion Thread  has finished:");
      }

      // Check if we have old entries in the names not found.
      Iterator it = _namesNotFound.keySet().iterator();
      long now = System.currentTimeMillis();
      while (it.hasNext()) {
        String name = (String) it.next();
        Date firstTime = (Date) _namesNotFound.get(name);
        if ( (now - firstTime.getTime()) > WARNING_IF_DN_NOT_FOUND) {
          if (loggingService.isWarnEnabled()) {
            loggingService.warn("Unable to get Certifificate entry for DN :"+ name);
          }
        }
      }
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
        if(loggingService.isDebugEnabled()){
          loggingService.debug("currentcrl is not null:");
        }
        currentset=currentcrl.getRevokedCertificates();
        if( currentset!=null) {
          if(loggingService.isDebugEnabled()){
            loggingService.debug("current set size is :"+currentset.size());
          }
        }
        else {
          if(loggingService.isDebugEnabled()){ 
            loggingService.debug("currentcrl set is null :");
          }
        }

      }
      if(oldcrl!=null) {
        if(loggingService.isDebugEnabled()){
          loggingService.debug("old crl is not null:");
        }
        oldset=oldcrl.getRevokedCertificates();
        if(oldset!=null) {
          if(loggingService.isDebugEnabled()){
            loggingService.debug("set size is :"+oldset.size());
          }
        }
        else { 
          if(loggingService.isDebugEnabled()){
            loggingService.debug("oldset crl  is null :");
          }
        }
      }
      else {
        if(loggingService.isDebugEnabled()){
          loggingService.debug("oldset crl  is null :");
        }
      }
      if(loggingService.isDebugEnabled()){
        loggingService.debug("Logging current as well as old crl set  :");
      }
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

    private CertDirectoryServiceClient getDirectoryService(String ldapURL,int ldapType) {
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
      if(loggingService.isDebugEnabled()){
        loggingService.debug("Crl are not equal as old crl is null ");
      }
      return false;
    }
    if(currentcrl==null) {
      if(loggingService.isDebugEnabled()){
        loggingService.debug("Crl are not equal as current  crl is null ");
      }
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
        if(loggingService.isDebugEnabled()){
          loggingService.debug("Size are equal for old as well as new crl :"+ "old:"+oldset.size()+
                               "new crl size"+ currentset.size());
        }
        equal=true;
      }
    }
    return equal;

  }

  private void dumpX509CRL(Set current,Set old) {
    if(loggingService.isDebugEnabled()){
      loggingService.debug(" Current crl set is :");
    }
    X509CRLEntry crlentry=null;
    if(current!=null) {
      Iterator iter=current.iterator();

      while(iter.hasNext()){
        crlentry=(X509CRLEntry)iter.next();
        if(crlentry!=null) {
          if(loggingService.isDebugEnabled()){
            loggingService.debug(" crl entry is  :"+crlentry.toString());
          }
        }
      }
    }
    if(loggingService.isDebugEnabled()){ 
      loggingService.debug(" Old crl set is :");
    }
    if(old!=null) {
      Iterator iter=old.iterator();
      while(iter.hasNext()){
        crlentry=(X509CRLEntry)iter.next();
        if(crlentry!=null) {
          if(loggingService.isDebugEnabled()){
            loggingService.debug(" crl entry is  :"+crlentry.toString());
          }
        }
      }
    }
  }
  private void event(String status, MessageAddress agent, String dn) {
    if (!eventService.isEventEnabled()) {
      return;
    }
    
    eventService.event("[STATUS] " + status 
                       + "(" + agentId +
                       ") Agent(" +
                       agent.toAddress() +
                       ") DN(" +
                       dn +
                       ")");
  }

}

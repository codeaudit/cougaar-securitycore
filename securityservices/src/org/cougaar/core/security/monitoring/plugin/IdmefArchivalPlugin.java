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


package org.cougaar.core.security.monitoring.plugin;

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.idmef.Agent;
import org.cougaar.core.security.monitoring.idmef.AgentRegistration;
import org.cougaar.core.security.monitoring.idmef.Registration;
import org.cougaar.core.service.EventService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.core.mts.MessageAddress;

import org.cougaar.core.security.services.util.SecurityPropertiesService;

import edu.jhuapl.idmef.IDMEF_Message;
import edu.jhuapl.idmef.Alert;

import java.util.Collections;
import java.util.Iterator;
import java.util.Date;
import java.util.List;
import java.util.LinkedList;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Calendar;
import java.util.Date;

import java.io.FileOutputStream;
import java.io.File;
import java.io.ObjectOutputStream;
import java.io.InvalidClassException;
import java.io.IOException;
import java.io.NotSerializableException;
import java.io.FileNotFoundException;


public class IdmefArchivalPlugin extends ComponentPlugin {
  
  private SecurityPropertiesService _secprop;
  private IncrementalSubscription _idmefevents;
  private LoggingService _log;
  private int _cacheSize = 100;
  private LinkedList _cache;
  private String topDir;
  private String nodeName;
  
  class BBIdmefEventPredicate implements UnaryPredicate{
    public boolean execute(Object o) {
      if (o instanceof Event) {
        IDMEF_Message msg = ((Event) o).getEvent();
        if (msg instanceof Registration ||
            msg instanceof AgentRegistration) {
          return false;
        }
        return (msg instanceof Alert);
      }
      return false;
    }
  }

  protected void setupSubscriptions() {
    _log = (LoggingService)getBindingSite().getServiceBroker().getService
      (this, LoggingService.class, null);
    if (_log.isDebugEnabled()) {
      _log.debug("IdmefArchivalPlugin setupSubscription()");
    }
    _idmefevents = (IncrementalSubscription)
      getBlackboardService().subscribe(new BBIdmefEventPredicate());
    _cache = new LinkedList();
    _secprop = (SecurityPropertiesService) getBindingSite().getServiceBroker().getService
      (this,SecurityPropertiesService.class, null);
    createTopDirStructure();
    
  }

  private void createTopDirStructure (){
    if(_secprop!=null) {
      //nodeName =  _secprop.getProperty("org.cougaar.node.name");
      MessageAddress myAddress = getAgentIdentifier();
      String cougaarws  = _secprop.getProperty(_secprop.COUGAAR_WORKSPACE);
      topDir= cougaarws + File.separatorChar + "security" + File.separatorChar + "IdmefEvent_Archival" + 
        File.separatorChar + myAddress.toString() ;
      File archivaldir = new File(topDir);
      if (!archivaldir.exists()) {
        archivaldir.mkdirs();
      }
    }
    else {
      if (_log.isWarnEnabled()) {
        _log.warn("Cannot get SecurityPropertiesService . ");
      }
    }
  }
  protected void execute () {
    Collection eventcollection = _idmefevents.getAddedCollection();
    if(!eventcollection.isEmpty()){
      Iterator eventiterator = eventcollection.iterator();
      while (eventiterator.hasNext()){
        Event event=(Event)eventiterator.next();
        _cache.add(event);
        //getBlackboardService().publishRemove(event);
      }
      if(_cache.size()>_cacheSize){
        try {
          removeAndArchive();
        }
        catch (FileNotFoundException fNotFoundexception){
          if (_log.isWarnEnabled()) {
            _log.warn("Cannot archive Idmef Events. "+fNotFoundexception.getMessage() );
          }
        }
        catch(NotSerializableException serialexception){
           if (_log.isWarnEnabled()) {
             _log.warn("Cannot archive Idmef Events. "+serialexception.getMessage() );
           }
        }
        catch (IOException ioexception) {
          if (_log.isWarnEnabled()) {
             _log.warn("Cannot archive Idmef Events. "+ioexception.getMessage() );
           }
          
        }
      }
    }
  }

  private void removeAndArchive() throws IOException,FileNotFoundException {
    File file=createArchiveFile();
    int noItems = _cache.size()- _cacheSize;
    Object event=null;
    List archivelist= new ArrayList();
    for (int i=0;i<noItems;i++) {
      event= _cache.removeFirst();
      archivelist.add(event);
      getBlackboardService().publishRemove(event);
    }
    if(file!=null){
      ObjectOutputStream  output=new ObjectOutputStream(new FileOutputStream(file));
      output.writeObject(archivelist);
      output.flush();
      output.close();
    }
    else {
      if (_log.isWarnEnabled()) {
        _log.warn("Cannot archive Idmef Events. Could not create  archive file ");
      }
    }
    
    
  }

  private File createArchiveFile() {
    Calendar cal= Calendar.getInstance();
    Date date=cal.getTime();
    String filename= topDir + File.separatorChar + nodeName+"-"+date.toString();
    File f= new File(filename); 
    return f;
  }
    
      
}

/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Inc
 *  under sponsorship of the Defense Advanced Research Projects
 *  Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS 
 *  PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR 
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF 
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT 
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT 
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL 
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS, 
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR 
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.  
 * 
 * </copyright>
 *
 * CHANGE RECORD
 * - 
 */

package org.cougaar.core.security.securebootstrap;

import java.util.Observable;
import java.util.Observer;
import java.util.ArrayList;
import java.util.Iterator;


public class EventHolder extends Observable  {

  private ArrayList events=null;
  private static EventHolder _instance;
  //private boolean atleastoneObserver=false;
  //private LoggingService log=null; 


  protected EventHolder() {
    //this.log=ls;
    events =new ArrayList(); 
  }

  
// For lazy initialization
  public static synchronized EventHolder getInstance() {
    
    if (_instance==null) {
      //System.out.println(" instance of event holder is null Creationg one:");
      _instance = new EventHolder();
    }
    
    return _instance;
  }
 

  public synchronized void   register (Observer o) {
    //System.out.println(" Observer is being added :"+o.toString());
    /*
    if(loggingService!=null) {
      loggingService.debug(" Observer is being added :"+o.toString());
    }
    */
    addObserver(o);
    //System.out.println(" No of observers is :"+ this.countObservers());
    //if(!atleastoneObserver)
    //atleastoneObserver=true;
    if((_instance.countObservers()>0)&&(events.size()>0)){
       ArrayList eventList=new ArrayList();
      Iterator iterator=events.iterator();
      while(iterator.hasNext()) {
	eventList.add((BootstrapEvent)iterator.next());
      }
      //System.out.println("Going to notify observers from register :"+eventList.size() );
      setChanged();
      notifyObservers(eventList);
      events.clear();
      clearChanged();
      // System.out.println(" clearing events in register:");
    }
    else {
      /*
      if(loggingService!=null) {
	 loggingService.debug(" No Observer to notify :");
	 loggingService.debug("Size of event queue :"+_instance.events.size());
       }
      */
      //System.out.println(" One of the conditions to notify observers has failed:");
      //System.out.println(" atleast one observer condition :"+atleastoneObserver);
      //System.out.println(" size of event queue :"+_instance.events.size());
    }
  }

    public synchronized void  remove (Observer o) {
      deleteObserver(o);
  }
  
  public void addEvent(BootstrapEvent o) {
    events.add(o);
    /*
    if(loggingService!=null) {
      loggingService.debug("Event are being added :");
    }
    */
    //System.out.println(" event are being added :"+ o.toString());
    //System.out.println(" event length after event is added is :"+events.size());
    if(_instance.countObservers()>0)  {
      
      ArrayList eventList=new ArrayList();
      Iterator iterator=_instance.events.iterator();
      while(iterator.hasNext()) {
	eventList.add((BootstrapEvent)iterator.next());
      }
      /*
      if(loggingService!=null) {
	loggingService.debug("Notifying Observers  :");
       }
      */
      setChanged();
      //System.out.println("Going to notify observers :");
      notifyObservers(eventList);
      //System.out.println(" clearing events in add event:");
      events.clear();
    }
    else {
      /*
       if(loggingService!=null) {
	loggingService.debug("No  Observers to notify   :");
       }
      */
      
    }
    //System.out.println(" No observers to Notify");
  }

}

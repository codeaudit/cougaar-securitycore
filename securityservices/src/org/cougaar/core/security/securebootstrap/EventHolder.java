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

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Collections;
import java.util.ListIterator;
import java.util.Iterator;
import java.util.Observable;
import java.util.Observer;
import java.util.Timer;
import java.util.TimerTask;


public class EventHolder extends Observable  {

  private List events=null;
  private static EventHolder _instance;
  //private boolean atleastoneObserver=false;
  //private LoggingService log=null; 
  private final long delay  =50;
  private boolean observerNotified=false;
  Timer timer=null;

  protected EventHolder() {
    //this.log=ls;
    events = Collections.synchronizedList(new LinkedList());
    timer=new Timer();
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
      timer.schedule(new NotifyTask(),delay);
    }
    else {
      /*
        if(loggingService!=null) {
        loggingService.debug(" No Observer to notify :");
        loggingService.debug("Size of event queue :"+_instance.events.size());
        }
      */
    }
  }

  public synchronized void  remove (Observer o) {
    deleteObserver(o);
  }
  
  public void addEvent(BootstrapEvent o) {
    ListIterator iter=events.listIterator();
    iter.add(o);
    timer.schedule(new NotifyTask(),delay);
  }
  
  /**
   * This class is used internally to notify observers when vere there is event in the queue.
   */
  class NotifyTask extends TimerTask {
    
    public NotifyTask() {
    }
    
    public void run() {
      if(_instance.countObservers()>0)  {
	ArrayList eventList=new ArrayList();
        ListIterator iterator=_instance.events.listIterator();
        while(iterator.hasNext()) {
          eventList.add((BootstrapEvent)iterator.next());
          iterator.remove();
        }
        _instance.setChanged();
        _instance.notifyObservers(eventList);
      }
      else {
        //System.out.println("No  Observers to notify   :");
        
      }
      
    }
  }

}

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


package org.cougaar.core.security.securebootstrap;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;
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
    int events_size = 0;
    synchronized (events) {
      events_size = events.size();
    }
    if((_instance.countObservers()>0)&&(events_size > 0)){
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
    synchronized (events) {
      ListIterator iter=events.listIterator();
      iter.add(o);
    }
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
        synchronized (_instance.events) {
          ListIterator iterator=_instance.events.listIterator();
          while(iterator.hasNext()) {
            eventList.add((BootstrapEvent)iterator.next());
            iterator.remove();
          }
        }
        // are the following thread safe?
        _instance.setChanged();
        _instance.notifyObservers(eventList);
      }
      else {
        //System.out.println("No  Observers to notify   :");
        
      }
      
    }
  }

}

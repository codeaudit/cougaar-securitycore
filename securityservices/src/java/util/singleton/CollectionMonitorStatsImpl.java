/*
 * <copyright>
 *  Copyright 2000-2003 Cougaar Software, Inc.
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
package java.util.singleton;

import java.util.*;
import java.lang.ref.Reference;
import java.lang.ref.WeakReference;

public class CollectionMonitorStatsImpl
  extends BaseSingleton
  implements CollectionMonitorStats
{
  private static CollectionMonitorStats _theInstance;
  private static long _startupTime;
  private static long DELAY_AFTER_STARTUP = 500;
  private static EntityStats _entityStats;

  protected CollectionMonitorStatsImpl() {
    //_entityStats = new EntityStats(null);
  }

  public static synchronized CollectionMonitorStats getInstance() {
    // Ugly hack to handle bootstrap issues.
    // When this method is invoked for the first time,
    // many things are not initialized yet.
    // For example, it is not possible to invoke System.out... methods,
    // It is not possible to get the ClassLoader, etc; This would cause
    // a VM initialization error.
    
    if (_startupTime == 0) {
      _startupTime = System.currentTimeMillis();
    }
    long now = System.currentTimeMillis();
    if ( (now - _startupTime) > DELAY_AFTER_STARTUP ) {
      //System.out.println("****");
      _theInstance = (CollectionMonitorStats)
	getInstance(CollectionMonitorStatsImpl.class,
		    CollectionMonitorStats.class,
		    _theInstance);
      //System.out.println("Instance: " + _theInstance);
    }
    else {
      if (_theInstance == null) {
	_theInstance = new CollectionMonitorStatsImpl();
      }
    }

    return _theInstance;
  }

  public EntityStats getEntityStats() {
    return _entityStats;
  }

  private void addElement(Object o, Class c) {
    long now = System.currentTimeMillis();
    if ( (now - _startupTime) > DELAY_AFTER_STARTUP ) {
      if (_entityStats == null) {
	_entityStats = new EntityStats(null);
      }
      EntityStats es = _entityStats.getEntityStats(c);
      if (es != null) {
	es.addCollection(o);
      }
      /*
      else {
	System.out.println("Error: unable to find EntityStats for " +
	  o.getClass().getName());
      }
      */
    }
  }

  public void addHashtable(Hashtable h) {
    addElement(h, Hashtable.class);
  }
  public void addArrayList(ArrayList l) {
    addElement(l, ArrayList.class);
  }
  public void addHashMap(HashMap m) {
    addElement(m, HashMap.class);
  }
  public void addHashSet(HashSet s) {
    addElement(s, HashSet.class);
  }
  public void addTreeMap(TreeMap m) {
    addElement(m, TreeMap.class);
  }
  public void addTreeSet(TreeSet s) {
    addElement(s, TreeSet.class);
  }
  public void addLinkedList(LinkedList l) {
    addElement(l, LinkedList.class);
  }
  public void addWeakHashMap(WeakHashMap m) {
    addElement(m, WeakHashMap.class);
  }
  public void addVector(Vector v) {
    addElement(v, Vector.class);
  }
  public void addArrays(Arrays a) {
    addElement(a, Arrays.class);
  }
  public void addStack(Stack s) {
    addElement(s, Stack.class);
  }
  public void addIdentityHashMap(IdentityHashMap m) {
    //addElement(m, IdentityHashMap.class);
  }
}

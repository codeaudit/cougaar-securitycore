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

import java.util.Map;
import java.util.List;
import java.util.Hashtable;
import java.util.HashSet;
import java.util.Set;
import java.util.Iterator;
import java.util.Collections;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.TreeSet;
import java.util.LinkedList;
import java.util.Stack;
import java.util.TreeMap;
import java.util.Vector;
import java.util.WeakHashMap;
import java.util.Comparator;
import java.util.Collection;
import java.util.IdentityHashMap;
import java.util.Arrays;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.ref.Reference;
import java.lang.ref.WeakReference;

public class EntityStats
{
  private Stats _stats;

  private Runnable _statsUpdater;

  /*
  private static ByteArrayOutputStream _bos;
  private static ObjectOutputStream _oos;
  */

  public static int UPDATE_STATS_FREQUENCY = 60 * 1000;

  /**
   * A map of all the instances of collections of the same type.
   * It maps Collections or Maps to EntityData
   */
  private Map       _collections;
  private Map       _agentStats;
  private Map       _componentStats;

  private Class     _type;

  /** All instances of EntityStats.
   * It maps a Class to an EntityStats.
   */
  //private static Map _collectionsMap;

  private static CollectionBinding _collectionBindings[] = {
    new CollectionBinding(Hashtable.class,
			  new EntityStats(Hashtable.class)),
    new CollectionBinding(HashSet.class,
			  new EntityStats(HashSet.class)),
    new CollectionBinding(HashMap.class,
			  new EntityStats(HashMap.class)),
    new CollectionBinding(ArrayList.class,
			  new EntityStats(ArrayList.class)),
    new CollectionBinding(IdentityHashMap.class,
			  new EntityStats(IdentityHashMap.class)),
    new CollectionBinding(LinkedHashMap.class,
			  new EntityStats(LinkedHashMap.class)),
    new CollectionBinding(LinkedHashSet.class,
			  new EntityStats(LinkedHashSet.class)),
    new CollectionBinding(LinkedList.class,
			  new EntityStats(LinkedList.class)),
    new CollectionBinding(Stack.class,
			  new EntityStats(Stack.class)),
    new CollectionBinding(TreeMap.class,
			  new EntityStats(TreeMap.class)),
    new CollectionBinding(TreeSet.class,
			  new EntityStats(TreeSet.class)),
    new CollectionBinding(Vector.class,
			  new EntityStats(Vector.class)),
    new CollectionBinding(WeakHashMap.class,
			  new EntityStats(WeakHashMap.class)),
    new CollectionBinding(Arrays.class,
			  new EntityStats(Arrays.class))
  };

  private static Object updaterLock = new Object();

  public EntityStats(Class type) {
    if (type != null) {
      _collections = new IdentityHashMap(true);
      /*
       * Update stats as a background thread. Otherwise, the IdentityHashMaps
       * may grow very large if the servlet is not invoked.
       */
      _statsUpdater = new Runnable() {
	  public void run() {
	    while (true) {
	      try {
		Thread.sleep(UPDATE_STATS_FREQUENCY);
	      }
	      catch (InterruptedException ex) {}
	      // Do only one update at a time.
	      synchronized (updaterLock) {
		//System.out.println("Updating stats for "
		//  + getShortName());
		updateIndividualCollectionSize();
	      }
	    }
	  }
	};
      Thread t = new Thread(_statsUpdater);
      t.setDaemon(true);
      t.setPriority(Thread.MIN_PRIORITY);
      t.start();
    }

    _type = type;
    _stats = new Stats();
    _agentStats = new HashMap(true);

   }

  public int getTotalAllocations(boolean update) {
    if (update) {
      updateCollections();
    }
    return _stats._totalAllocations;
  }

  /** Return a the collectionMap
   */
  public CollectionBinding[] getCollections() {
    return _collectionBindings;
  }

  public EntityStats getEntityStats(Class type) {
    for (int i = 0 ; i < _collectionBindings.length ; i++) {
      if(_collectionBindings[i].getType().getName().equals(type.getName())) {
	return _collectionBindings[i].getEntityStats();
      }
    }
    return null;
    //return (EntityStats) _collectionsMap.get(type);
  }

  public EntityStats getEntityStats(String type) {
    Class cl = null;
    if (type == null) {
      return null;
    }
    try {
      cl = Class.forName(type);
    }
    catch (ClassNotFoundException e) {}
    if (cl == null) {
      return null;
    }
    return getEntityStats(cl);
  }


  /*
  public static synchronized long getObjectSize(Object o) {
    _bos.reset();
    try {
      _oos.writeObject(o);
    }
    catch (java.io.IOException ex) {
      // Probably not serializable
    }
    long ret = _bos.size();
    _bos.reset();
    return ret;
  }
  */

  /**
   * The number of collections currently allocated (that haven't been
   * garbage collected)
   */
  public int getCurrentAllocations(boolean update) {
    if (update) {
      // Remove all WeakReferences
      updateIndividualCollectionSize();
      //updateCollections();
    }
    int ret = 0;
    synchronized (_collections) {
      ret = _collections.size();
    }
    return ret;
  }

  public void updateCollections() {
    synchronized (_collections) {
      Iterator it = _collections.entrySet().iterator();

      while (it.hasNext()) {
	Map.Entry me = (Map.Entry) it.next();
	Reference wr = (Reference) me.getKey();
	if (wr.get() == null) {
	  // This is the last chance to have access to the
	  // per-agent and per-component stats.
	  // Update those stats.
	  EntityData ed = (EntityData) me.getValue();
	  it.remove();

	  /*
	  synchronized(_agentStats) {
	    Stats st = (Stats) _agentStats.get(ed.getAgentName());
	    if (st == null) {
	      st = new Stats();
	      _agentStats.put(ed.getAgentName(), st);
	    }
	    st._garbageCollected++;
	  }
	  */
	  _stats._garbageCollected++;
	}
      }
    }
  }

  public List updateIndividualCollectionSize() {
    updateCollections();
    List l = null;
    synchronized (_collections) {
      l = new ArrayList(_collections.entrySet());
      Iterator it = l.iterator();
      long sum = 0;
      while (it.hasNext()) {
	Map.Entry m = (Map.Entry) it.next();
	if (m != null) {
	  EntityData ed = (EntityData) m.getValue();
	  ed.updateCurrentSize();
	  sum += (long) ed.getCurrentSize(false);
	}
	else {
	  System.out.println("Error: no Map.Entry");
	}
      }
      _stats._totalNumberOfElements = sum;
    }
    return l;
  }

  public Class getType() {
    return _type;
  }

  public String getShortName() {
    String s = _type.getName();
    return s.substring(s.lastIndexOf('.') + 1, s.length());
  }

  public int getGarbageCollected(boolean update) {
    if (update) {
      updateCollections();
    }
    return _stats._garbageCollected;
  }

  public void addCollection(Object o) {
    EntityData ed = new EntityData(new Throwable(), o, _type);
    synchronized(_collections) {
      _collections.put(new WeakReference(o), ed);
      _stats._totalAllocations++;
    }
  }

  public long getTotalNumberOfElements(boolean update) {
    if (update) {
      updateIndividualCollectionSize();
    }
    return _stats._totalNumberOfElements;
  }

  public double getMedianSize(boolean update) {
    if (update) {
      getTopCollections(1, QUERY_ALL, null);
    }
    return _stats._medianSize;
  }

  public List getAgentStats(String agentName) {
    List agentList = new ArrayList();

    List entries = updateIndividualCollectionSize();
    Iterator it = entries.iterator();
    while (it.hasNext()) {
      Map.Entry m = (Map.Entry) it.next();
      EntityData ed = (EntityData) m.getValue();
      if (ed.getAgentName() == null && agentName == null) {
	agentList.add(m);
      }
      if (ed.getAgentName() != null &&
	  ed.getAgentName().equals(agentName)) {
	agentList.add(m);
      }
    }
    return agentList;
  }

  public Map getAgentStats() {
    // First, clear some stats
    synchronized (_agentStats) {
      Collection c = _agentStats.values();
      Iterator it = c.iterator();
      while (it.hasNext()) {
	Stats st = (Stats) it.next();
	st._currentAllocations = 0;
	st._totalNumberOfElements = 0;
      }
    }

    synchronized (_collections) {
      List entries = updateIndividualCollectionSize();
      Iterator it = entries.iterator();
      while (it.hasNext()) {
	Map.Entry m = (Map.Entry) it.next();
	EntityData ed = (EntityData) m.getValue();

	synchronized (_agentStats) {
	  Stats st = (Stats) _agentStats.get(ed.getAgentName());
	  if (st == null) {
	    st = new Stats();
	    _agentStats.put(ed.getAgentName(), st);
	  }

	  // Update stats
	  st._currentAllocations++;
	  st._totalNumberOfElements += ed.getCurrentSize(false);
	
	  // We could increment a counter every time a collection is created,
	  // but this would require to lookup the subject information.
	  st._totalAllocations = st._currentAllocations +
	    st._garbageCollected;
	}
      }
    }
    return _agentStats;
  }

  public List getCollectionsByComponent() {
    List l = null;
    synchronized (_collections) {
      l = updateIndividualCollectionSize();
      Collections.sort(l, new ComponentComparator());
    }
    return l;
  }

  public static final int QUERY_ALL = 1;
  public static final int QUERY_AGENT = 2;
  public static final int QUERY_COMPONENT = 3;

  public List getTopCollections(int topNumber,
				int queryType,
				String agentName) {
    List ret = null;
    List l = null;
    switch (queryType) {
    case QUERY_ALL:
      l = updateIndividualCollectionSize();
      Collections.sort(l, new SizeComparator());
      break;
    case QUERY_AGENT:
      l = getAgentStats(agentName);
      Collections.sort(l, new AgentComparator());
      break;
    case QUERY_COMPONENT:
      Collections.sort(l, new ComponentComparator());
      break;
    default:
      throw new IllegalArgumentException("Wrong query type:" + queryType);
    }

    // Update averaged median size
    updateMedianSize(l);

    topNumber = Math.min(topNumber, l.size());
    try {
      ret = new ArrayList(l.subList(0, topNumber));
    }
    catch (IndexOutOfBoundsException e) {
      System.out.println("Error: " + e);
    }
    return ret;
  }

  private void updateMedianSize(List collection) {
    // Update averaged median size
    int n = collection.size();
    if (n > 0) {
      Map.Entry me1 = (Map.Entry) collection.get((int)Math.ceil((n-1)/2));
      Map.Entry me2 = (Map.Entry) collection.get((int)Math.ceil(n/2));
      double x1 = (double)
	((EntityData)(me1.getValue())).getCurrentSize(false);
      double x2 = (double)
	((EntityData)(me2.getValue())).getCurrentSize(false);
      _stats._medianSize = (x1 + x2) / 2.0;
    }
  }

  // comparators
  /**
   * Sort in descending order of collection sizes.
   */
  public class SizeComparator implements Comparator
  {
    public int compare(Object o1, Object o2) {
      return ((EntityData) ((Map.Entry) o2).getValue()).getCurrentSize(false) -
	     ((EntityData) ((Map.Entry) o1).getValue()).getCurrentSize(false);
    }
  }

  /**
   * Sort first by component name (alphabetical order), then 
   * in descending order of collection sizes.
   */
  public class ComponentComparator implements Comparator
  {
    public int compare(Object o1, Object o2) {
      EntityData ed1 = ((EntityData) ((Map.Entry) o1).getValue());
      EntityData ed2 = ((EntityData) ((Map.Entry) o2).getValue());
      String component1 = ed1.getComponentName();
      String component2 = ed2.getComponentName();

      if (component1 == null && component2 != null) {
	return -1;
      }
      else if (component1 != null && component2 == null) {
	return 1;
      }
      else if (component1 == null && component2 == null) {
	return ed2.getCurrentSize(false) -
	  ed1.getCurrentSize(false);
      }
      else {
	int componentCompare = component1.compareTo(component2);
	if (componentCompare != 0) {
	  return componentCompare;
	}
	else {
	  return ed2.getCurrentSize(false) -
	    ed1.getCurrentSize(false);
	}
      }
    }
  }

  /**
   * Sort first by agent name (alphabetical order), then 
   * in descending order of collection sizes.
   */
  public class AgentComparator implements Comparator
  {
    public int compare(Object o1, Object o2) {
      EntityData ed1 = ((EntityData) ((Map.Entry) o1).getValue());
      EntityData ed2 = ((EntityData) ((Map.Entry) o2).getValue());
      String agent1 = ed1.getAgentName();
      String agent2 = ed2.getAgentName();

      if (agent1 == null && agent2 != null) {
	return 1;
      }
      else if (agent1 != null && agent2 == null) {
	return -1;
      }
      else if (agent1 == null && agent2 == null) {
	return ed2.getCurrentSize(false) -
	  ed1.getCurrentSize(false);
      }
      else {
	int agentCompare = agent2.compareTo(agent1);
	if (agentCompare != 0) {
	  return agentCompare;
	}
	else {
	  return ed2.getCurrentSize(false) -
	    ed1.getCurrentSize(false);
	}
      }
    }
  }

  public static class CollectionBinding {
    private Class _type;
    private EntityStats _entityStats;

    public CollectionBinding(Class t, EntityStats es) {
      _type = t;
      _entityStats = es;
    }

    public Class getType() {
      return _type;
    }

    public EntityStats getEntityStats() {
      return _entityStats;
    }
  }
  
  public static class Stats {
    /**
     * The total number of times the collection was allocated.
     */
    public int       _totalAllocations;

    /**
     * The number of currently allocated collections
     */
    public int       _currentAllocations;

    /**
     * The number of collections that have been garbage collected.
     */
    public int       _garbageCollected;

    /***
     * The total of all elements in the collections.
     */
    public long      _totalNumberOfElements;

    /***
     * The median size of the collections.
     */
    public double    _medianSize;

  }

}

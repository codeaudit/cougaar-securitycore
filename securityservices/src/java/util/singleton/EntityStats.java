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
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.ref.Reference;
import java.lang.ref.WeakReference;

public class EntityStats
{
  private Stats _stats;
  private static ByteArrayOutputStream _bos;
  private static ObjectOutputStream _oos;

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
			  new EntityStats(WeakHashMap.class))
  };

  public EntityStats(Class type) {
    if (type != null) {
      _collections = new IdentityHashMap();
    }
    _type = type;
    _stats = new Stats();
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
    try {
      cl = Class.forName(type);
    }
    catch (ClassNotFoundException e) {}
    if (cl == null) {
      return null;
    }
    return getEntityStats(cl);
  }


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
    return _collections.size();
  }

  public void updateCollections() {
    synchronized (_collections) {
      Set s = _collections.entrySet();
      Iterator it = s.iterator();
      while (it.hasNext()) {
	Reference wr = (Reference) ((Map.Entry) it.next()).getKey();
	if (wr.get() == null) {
	  it.remove();
	  _stats._garbageCollected++;
	}
      }
    }
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

  public List updateIndividualCollectionSize() {
    updateCollections();
    List l = new ArrayList(_collections.entrySet());
    Iterator it = l.iterator();
    long sum = 0;
    while (it.hasNext()) {
      Map.Entry m = (Map.Entry) it.next();
      EntityData ed = (EntityData) m.getValue();
      ed.updateCurrentSize();
      sum += (long) ed.getCurrentSize(false);
    }
    _stats._totalNumberOfElements = sum;
    return l;
  }

  public long getTotalNumberOfElements(boolean update) {
    if (update) {
      updateIndividualCollectionSize();
    }
    return _stats._totalNumberOfElements;
  }

  public double getMedianSize(boolean update) {
    if (update) {
      getTopCollections(1);
    }
    return _stats._medianSize;
  }

  public Map getAgentStats() {
    List l = updateIndividualCollectionSize();
    Collections.sort(l, new AgentComparator());
    Iterator it = l.iterator();

    if (_agentStats == null) {
      _agentStats = new HashMap();
    }
    String agentName = "deadbeef0123";
    Stats agentStats = null;
    while (it.hasNext()) {
      Map.Entry m = (Map.Entry) it.next();
      EntityData ed = (EntityData) m.getValue();
      if (ed.getAgentName() != agentName) {
	agentName = ed.getAgentName();
	agentStats = new Stats();
	_agentStats.put(agentName, agentStats);
      }
      // Update stats
      agentStats._currentAllocations++;
      agentStats._totalNumberOfElements += ed.getCurrentSize(false);
    }
    return _agentStats;
  }

  public List getCollectionsByComponent() {
    List l = updateIndividualCollectionSize();
    Collections.sort(l, new ComponentComparator());
    return l;
  }

  public List getTopCollections(int topNumber) {
    List l = updateIndividualCollectionSize();
    List ret = null;
    Collections.sort(l, new SizeComparator());

    // Update averaged median size
    updateMedianSize(l);

    topNumber = Math.min(topNumber, l.size());
    try {
      ret = l.subList(0, topNumber);
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
	return -1;
      }
      else if (agent1 != null && agent2 == null) {
	return 1;
      }
      else if (agent1 == null && agent2 == null) {
	return ed2.getCurrentSize(false) -
	  ed1.getCurrentSize(false);
      }
      else {
	int agentCompare = agent1.compareTo(agent2);
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
}

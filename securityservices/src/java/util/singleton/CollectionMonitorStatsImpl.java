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

  private Map _hashtableStats;
  private Map _arrayListStats;
  private Map _hashMapStats;
  private Map _hashSetStats;
  private Map _identityHashMapStats;
  private Map _linkedListStats;
  private Map _weakHashMapStats;
  private Map _treeMapStats;
  private Map _treeSetStats;

  protected CollectionMonitorStatsImpl() {
    
    _hashtableStats = new IdentityHashMap();
    _arrayListStats = new IdentityHashMap();
    _hashMapStats = new IdentityHashMap();
    _hashSetStats = new IdentityHashMap();
    _identityHashMapStats = new IdentityHashMap();
    _linkedListStats = new IdentityHashMap();
    _weakHashMapStats = new IdentityHashMap();
    _treeMapStats = new IdentityHashMap();
    _treeSetStats = new IdentityHashMap();

  }

  private static long DELAY_AFTER_STARTUP = 100;

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

  // hashtables
  public int getNumberOfHashtables() {
    Set s = _hashtableStats.entrySet();
    List l = updateEntries(s);
    return _hashtableStats.size();
  }
  public List getTopHashtables(int topNumber) {
    Set s = _hashtableStats.entrySet();
    List l = updateEntries(s);
    Collections.sort(l, new SizeComparator());
    return l.subList(0, topNumber);
  }
  public void addHashtable(Hashtable h) {
    synchronized (_hashtableStats) {
      _p++;
      _hashtableStats.put(new WeakReference(h), new EntityData(new Throwable()));
    }
    /*
    long now = System.currentTimeMillis();
    if ( (now - _startupTime) > DELAY_AFTER_STARTUP ) {
      System.out.println("Add Hashtable: " + _p + " - " + this);
    }
    */
  }
  private int _p;

  // array list
  public int getNumberOfArrayLists() {
    Set s = _arrayListStats.entrySet();
    List l = updateEntries(s);
    return _arrayListStats.size();
  }
  public List getTopArrayLists(int topNumber) {
    Set s = _arrayListStats.entrySet();
    List l = updateEntries(s);
    Collections.sort(l, new SizeComparator());
    return l.subList(0, topNumber);
  }
  public void addArrayList(ArrayList l) {
    synchronized (_arrayListStats) {
      _arrayListStats.put(new WeakReference(l), new EntityData(new Throwable()));
    }
  }

  // hash map
  public int getNumberOfHashMaps() {
    Set s = _hashMapStats.entrySet();
    List l = updateEntries(s);
    return _hashMapStats.size();
  }
  public List getTopHashMaps(int topNumber) {
    Set s = _hashMapStats.entrySet();
    List l = updateEntries(s);
    Collections.sort(l, new SizeComparator());
    return l.subList(0, topNumber);
  }
  public void addHashMap(HashMap m) {
    synchronized (_hashMapStats) {
      _hashMapStats.put(new WeakReference(m), new EntityData(new Throwable()));
    }
  }

  // hash set
  public int getNumberOfHashSets() {
    Set s = _hashSetStats.entrySet();
    List l = updateEntries(s);
    return _hashSetStats.size();
  }
  public List getTopHashSets(int topNumber) {
    Set s = _hashSetStats.entrySet();
    List l = updateEntries(s);
    Collections.sort(l, new SizeComparator());
    return l.subList(0, topNumber);
  }
  public void addHashSet(HashSet s) {
    synchronized (_hashSetStats) {
      _hashSetStats.put(new WeakReference(s), new EntityData(new Throwable()));
    }
  }

  // tree map
  public int getNumberOfTreeMaps() {
    Set s = _treeMapStats.entrySet();
    List l = updateEntries(s);
    return _treeMapStats.size();
  }
  public List getTopTreeMaps(int topNumber) {
    Set s = _treeMapStats.entrySet();
    List l = updateEntries(s);
    Collections.sort(l, new SizeComparator());
    return l.subList(0, topNumber);
  }
  public void addTreeMap(TreeMap m) {
    synchronized (_treeMapStats) {
      _treeMapStats.put(new WeakReference(m), new EntityData(new Throwable()));
    }
  }

  // tree set
  public int getNumberOfTreeSets() {
    Set s = _treeSetStats.entrySet();
    List l = updateEntries(s);
    return _treeSetStats.size();
  }
  public List getTopTreeSets(int topNumber) {
    Set s = _treeSetStats.entrySet();
    List l = updateEntries(s);
    Collections.sort(l, new SizeComparator());
    return l.subList(0, topNumber);
  }
  public void addTreeSet(TreeSet s) {
    synchronized (_treeSetStats) {
      _treeSetStats.put(new WeakReference(s), new EntityData(new Throwable()));
    }
  }

  // linked list
  public int getNumberOfLinkedLists() {
    Set s = _linkedListStats.entrySet();
    List l = updateEntries(s);
    return _linkedListStats.size();
  }
  public List getTopLinkedLists(int topNumber) {
    Set s = _linkedListStats.entrySet();
    List l = updateEntries(s);
    Collections.sort(l, new SizeComparator());
    return l.subList(0, topNumber);
  }
  public void addLinkedList(LinkedList l) {
    synchronized (_linkedListStats) {
      _linkedListStats.put(new WeakReference(l), new EntityData(new Throwable()));
    }
  }

  // weak hash map
  public int getNumberOfWeakHashMaps() {
    Set s = _weakHashMapStats.entrySet();
    List l = updateEntries(s);
    return _weakHashMapStats.size();
  }
  public List getTopWeakHashMaps(int topNumber) {
    // Take a snapshot. Trying to sort on the set may not work
    // as the collection may change while we are trying to sort it.
    Set s = _weakHashMapStats.entrySet();
    List l = updateEntries(s);
    Collections.sort(l, new SizeComparator());
    return l.subList(0, topNumber);
  }
  public void addWeakHashMap(WeakHashMap m) {
    synchronized (_weakHashMapStats) {
      _weakHashMapStats.put(new WeakReference(m), new EntityData(new Throwable()));
    }
  }

  // identity hash map
  public int getNumberOfIdentityHashMaps() {
    Set s = _identityHashMapStats.entrySet();
    List l = updateEntries(s);
    return _identityHashMapStats.size();
  }
  public List getTopIdentityHashMaps(int topNumber) {
    Set s = _identityHashMapStats.entrySet();
    List l = updateEntries(s);
    Collections.sort(l, new SizeComparator());
    return l.subList(0, topNumber);
  }
  public void addIdentityHashMap(IdentityHashMap m) {
    synchronized (_identityHashMapStats) {
      _identityHashMapStats.put(new WeakReference(m), new EntityData(new Throwable()));
    }
  }

  public List updateEntries(Set s) {
    System.out.println("Set size: " + s.size());
    Iterator it = s.iterator();
    int removed = 0;
    while (it.hasNext()) {
      Reference wr = (Reference) ((Map.Entry) it.next()).getKey();
      if (wr.get() == null) {
	//synchronized(this) {
	  it.remove();
	  //}
	removed++;
      }
    }
    System.out.println("Set size: " + s.size() +
		       " - Removed " + removed + " entries");

    List l = new ArrayList(s);
    it = l.iterator();
    while (it.hasNext()) {
      Map.Entry m = (Map.Entry) it.next();
      EntityData e = (EntityData) m.getValue();
      if ( ((Reference)m.getKey()).get() instanceof Collection) {
	e._size = ((Collection) ( (Reference) m.getKey()).get()).size();
      }
      else if ( ((Reference)m.getKey()).get() instanceof Map) {
	e._size = ( (Map) ( (Reference) m.getKey()).get()).size();
      }
    }
    return l;
  }

  // comparators
  public class SizeComparator implements Comparator
  {
    public int compare(Object o1, Object o2) {
      return ((EntityData) ((Map.Entry) o2).getValue())._size -
	     ((EntityData) ((Map.Entry) o1).getValue())._size;
    }
  }
/*
  public class ListSizeComparator implements Comparator
  {
    public int compare(Object o1, Object o2) {
      return ((List) ((Map.Entry) o2).getKey()).size() -
	     ((List) ((Map.Entry) o1).getKey()).size();
    }
  }
  public class MapSizeComparator implements Comparator
  {
    public int compare(Object o1, Object o2) {
      return ((Map) ((Map.Entry) o2).getKey()).size() -
	     ((Map) ((Map.Entry) o1).getKey()).size();
    }
  }
  public class SetSizeComparator implements Comparator
  {
    public int compare(Object o1, Object o2) {
      return ((Set) ((Map.Entry) o2).getKey()).size() -
	     ((Set) ((Map.Entry) o1).getKey()).size();
    }
  }

  public class HashtableSizeComparator implements Comparator
  {
    public int compare(Object o1, Object o2) {
      return ((Hashtable) ((Map.Entry) o2).getKey()).size() -
	     ((Hashtable) ((Map.Entry) o1).getKey()).size();
    }
  }
*/
  public static class EntityData {
    public Throwable _throwable;
    public int       _size;
    public EntityData(Throwable t) {
      _throwable = t;
    }
  }
}

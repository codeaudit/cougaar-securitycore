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
package org.cougaar.core.security.test.memory;

import java.util.*;

public class CollectionMonitorStats
{
  
  private static CollectionMonitorStats _theInstance;
  private List _hashtableStats;
  private List _arrayListStats;
  private List _hashMapStats;
  private List _hashSetStats;

  CollectionMonitorStats() {
    _hashtableStats = new ArrayList();
    _arrayListStats = new ArrayList();
    _hashMapStats = new ArrayList();
    _hashSetStats = new ArrayList();
  }

  public static synchronized CollectionMonitorStats getInstance() {
    if (_theInstance == null) {
      _theInstance = new CollectionMonitorStats();
    }
    return _theInstance;
  }

  public int getNumberOfHashtables() {
    return _hashtableStats.size();
  }
  public List getTopHashtables(int topNumber) {
    Collections.sort(_hashtableStats, new HashtableSizeComparator());
    return _hashtableStats.subList(0, topNumber);
  }
  public void addHashtable(Hashtable h) {
    synchronized (_hashtableStats) {
      _hashtableStats.add(new HashtableStats(new Throwable(), h));
    }
  }

  public static class HashtableStats
    implements Stats
  {
    private Throwable _t;
    private Hashtable _h;

    public HashtableStats(Throwable t, Hashtable h) {
      _t = t;
      _h = h;
    }

    public Throwable getThrowable() {
      return _t;
    }
    public Object getCollection() {
      return _h;
    }
  }

  public class HashtableSizeComparator implements Comparator
  {
    public int compare(Object o1, Object o2) {
      if (!(o1 instanceof HashtableStats) || !(o2 instanceof HashtableStats)) {
	throw new ClassCastException("Not the right type");
      }
      Hashtable h1 = (Hashtable) ((HashtableStats)o1).getCollection();
      Hashtable h2 = (Hashtable) ((HashtableStats)o2).getCollection();
      Integer i1 = new Integer(h1.size());
      Integer i2 = new Integer(h2.size());
      return (i2.compareTo(i1));
    }
 
  }
}

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

public interface CollectionMonitorStats
{
  public int getNumberOfHashtables();
  public List getTopHashtables(int topNumber);
  public void addHashtable(Hashtable h);

  public int getNumberOfArrayLists();
  public List getTopArrayLists(int topNumber);
  public void addArrayList(ArrayList l);

  public int getNumberOfHashMaps();
  public List getTopHashMaps(int topNumber);
  public void addHashMap(HashMap m);

  public int getNumberOfHashSets();
  public List getTopHashSets(int topNumber);
  public void addHashSet(HashSet s);

  public int getNumberOfTreeMaps();
  public List getTopTreeMaps(int topNumber);
  public void addTreeMap(TreeMap m);

  public int getNumberOfTreeSets();
  public List getTopTreeSets(int topNumber);
  public void addTreeSet(TreeSet s);

  public int getNumberOfLinkedLists();
  public List getTopLinkedLists(int topNumber);
  public void addLinkedList(LinkedList l);
  
  public int getNumberOfWeakHashMaps();
  public List getTopWeakHashMaps(int topNumber);
  public void addWeakHashMap(WeakHashMap m);

  public int getNumberOfIdentityHashMaps();
  public List getTopIdentityHashMaps(int topNumber);
  public void addIdentityHashMap(IdentityHashMap m);
}

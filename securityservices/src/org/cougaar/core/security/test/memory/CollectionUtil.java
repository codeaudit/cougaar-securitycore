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

import java.util.List;

public class CollectionUtil {
  public static final int HASH_TABLE          = 1;
  public static final int HASH_SET            = 2;
  public static final int HASH_MAP            = 3;
  public static final int ARRAY_LIST          = 4;
  public static final int IDENTITY_HASH_MAP   = 5;
  public static final int LINKED_HASH_MAP     = 6;
  public static final int LINKED_HASH_SET     = 7;
  public static final int LINKED_LIST         = 8;
  public static final int STACK               = 9;
  public static final int TREE_MAP            = 10;
  public static final int TREE_SET            = 11;
  public static final int VECTOR              = 12;
  public static final int WEAK_HASH_MAP       = 13;

  private CollectionMonitorStats _stats;
  private static CollectionUtil _theInstance;

  CollectionUtil() {
    _stats = CollectionMonitorStats.getInstance();
  }

  public static synchronized CollectionUtil getInstance() {
    if (_theInstance == null) {
      _theInstance = new CollectionUtil();
    }
    return _theInstance;
  }

  public int getNumberOfElements(int type) {
    int ret = -1;
    switch (type) {
    case HASH_TABLE:
      ret = _stats.getNumberOfHashtables();
      break;
    case HASH_SET:
      ret = _stats.getNumberOfHashSets();
      break;
    case HASH_MAP:
      ret = _stats.getNumberOfHashMaps();
      break;
    case ARRAY_LIST:
      ret = _stats.getNumberOfArrayLists();
      break;
    case IDENTITY_HASH_MAP:
      ret = _stats.getNumberOfIdentityHashMaps();
      break;
    case LINKED_HASH_MAP:
      //ret = _stats.getNumberOfLinkedHashMaps();
      break;
    case LINKED_HASH_SET:
      //ret = _stats.getNumberOfLinkedHashSets();
      break;
    case LINKED_LIST:
      ret = _stats.getNumberOfLinkedLists();
      break;
    case STACK:
      //ret = _stats.getNumberOfStacks();
      break;
    case TREE_MAP:
      ret = _stats.getNumberOfTreeMaps();
      break;
    case TREE_SET:
      ret = _stats.getNumberOfTreeSets();
      break;
    case VECTOR:
      //ret = _stats.getNumberOfVectors();
      break;
    case WEAK_HASH_MAP:
      ret = _stats.getNumberOfWeakHashMaps();
      break;
    default:
      ret = -1;
    }

    return ret;
  }

  public List getTopElements(int type, int top) {
    List l = null;
    switch (type) {
    case HASH_TABLE:
      l = _stats.getTopHashtables(top);
      break;
    case HASH_SET:
      l = _stats.getTopHashSets(top);
      break;
    case HASH_MAP:
      l = _stats.getTopHashMaps(top);
      break;
    case ARRAY_LIST:
      l = _stats.getTopArrayLists(top);
      break;
    case IDENTITY_HASH_MAP:
      l = _stats.getTopIdentityHashMaps(top);
      break;
    case LINKED_HASH_MAP:
      //l = _stats.getTopLinkedHashMaps(top);
      break;
    case LINKED_HASH_SET:
      //l = _stats.getTopLinkedHashSets(top);
      break;
    case LINKED_LIST:
      l = _stats.getTopLinkedLists(top);
      break;
    case STACK:
      //l = _stats.getTopStacks(top);
      break;
    case TREE_MAP:
      l = _stats.getTopTreeMaps(top);
      break;
    case TREE_SET:
      l = _stats.getTopTreeSets(top);
      break;
    case VECTOR:
      //l = _stats.getTopVectors(top);
      break;
    case WEAK_HASH_MAP:
      l = _stats.getTopWeakHashMaps(top);
      break;
    default:
      l = null;
    }
    return l;
  }
}

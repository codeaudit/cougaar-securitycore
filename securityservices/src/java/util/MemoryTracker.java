package java.util;

import java.util.singleton.*;

public class MemoryTracker {
  static CollectionMonitorStats m;

  static {
    m = CollectionMonitorStatsImpl.getInstance();
  }
  public static void add(Object o) {
    // when MemoryTracker is created it will create m and this function will be
    // called with m null.
    if (m == null) {
      return;
    }
    if (o instanceof ArrayList) {
      m.addArrayList((ArrayList)o);
    }
    else if (o instanceof HashMap) {
      m.addHashMap((HashMap)o);
    }
    else if (o instanceof Hashtable) {
      m.addHashtable((Hashtable)o);
    }
    else if (o instanceof HashSet) {
      m.addHashSet((HashSet)o);
    }
    else if (o instanceof IdentityHashMap) {
      m.addIdentityHashMap((IdentityHashMap)o);
    }
    else if (o instanceof LinkedList) {
      m.addLinkedList((LinkedList)o);
    }
    else if (o instanceof WeakHashMap) {
      m.addWeakHashMap((WeakHashMap)o);
    }
    else if (o instanceof TreeMap) {
      m.addTreeMap((TreeMap)o);
    }
    else if (o instanceof TreeSet) {
      m.addTreeSet((TreeSet)o);
    }
    else if (o instanceof Vector) {
      m.addVector((Vector)o);
    }
    else if (o instanceof Stack) {
      m.addStack((Stack)o);
    }
    else if (o instanceof Arrays) {
      m.addArrays((Arrays)o);
    }
    else if (o instanceof LinkedHashMap) {
      m.addLinkedHashMap((LinkedHashMap)o);
    }
    else if (o instanceof LinkedHashSet) {
      m.addLinkedHashSet((LinkedHashSet)o);
    }
/*
    if (o instanceof AbstractList) {
      m.addList(o);
    }
    else if (o instanceof AbstractMap) {
      m.addMap(o);
    }
    else if (o instanceof AbstractSet) {
      m.addSet(o);
    }
    else if (o instanceof AbstractSequentialList) {
      m.addLinkedList(o);
    }
    else if (o instanceof Dictionary) {
      m.addHashtable(o);
    }
*/
     
  }
}

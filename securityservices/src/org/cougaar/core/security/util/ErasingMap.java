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

 
package org.cougaar.core.security.util;
import java.util.AbstractMap;
import java.util.AbstractSet;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

public class ErasingMap extends AbstractMap {

  private static final Comparator COMPARE_DATES = new CompareDates();

  long       _maxAge  = 60 * 1000 * 1000;
  Map        _values  = new HashMap();
  SortedSet  _dateSet = new TreeSet(COMPARE_DATES);
  long       _lastCheck = System.currentTimeMillis();

  public ErasingMap() {}

  public ErasingMap(long maxAge) { 
    _maxAge = maxAge;
  }

  public Set entrySet() {
    return new BackedEntrySet();
  }

  public Set keySet() {
    return new BackedKeySet();
  }

  public Object get(Object key) {
    DatedElement d = (DatedElement) _values.get(key);
    if (d == null) {
      return null;
    }
    return d.val;
  }

  public Object put(Object key, Object value) {
    DatedElement d      = (DatedElement) _values.get(key);
    Object       oldVal = null;
    if (d != null) {
      oldVal = d.val;
      _dateSet.remove(d);
      d.val = value;
    } else {
      d = new DatedElement(key, value);
      _values.put(key, d);
    }
    d.update();
    _dateSet.add(d);
    checkErase(d.date);
    return oldVal;
  }

  private void checkErase(long date) {
    if ((date - _lastCheck) > (_maxAge/2)) {
      _lastCheck = date;
      DatedElement d = new DatedElement(null, null);
      d.date = date - _maxAge;
      Set outOfDate = _dateSet.tailSet(d);
      Iterator iter = outOfDate.iterator();
      while (iter.hasNext()) {
        d = (DatedElement) iter.next();
        _values.remove(d.key);
        iter.remove();
      }
    }
  }

  public Object remove(Object o) {
    DatedElement d = (DatedElement) _values.remove(o);
    if (d == null) {
      return null;
    }

    _dateSet.remove(d);
    checkErase(System.currentTimeMillis());
    return d.val;
  }

  public static void main(String args[]) {
    ErasingMap map = new ErasingMap();
    for (int i = 0; i < 100; i++) {
      Integer objI = new Integer(i);
      map.put(objI, objI);
    }

    if (map.size() != 100) {
      System.out.println("map should be size 100");
    }

    for (int i = 0; i < 100; i++) {
      Integer objI = new Integer(i);
      Integer objJ = (Integer) map.get(objI);
      if (!objI.equals(objJ)) {
        System.out.println("Did not receive the right object. Got " + objJ +
                           " but was expecting " + objI);
      }
    }
    
    Iterator iter = map.keySet().iterator();
    while (iter.hasNext()) {
      Object o = iter.next();
      if (!o.equals(map.get(o))) {
        System.out.println("Expecting " + o + " but didn't get it");
      }
      iter.remove();
    }
    if (map.size() != 0) {
      System.out.println("Size should be zero, but got " + map.size());
    }
    System.out.println("Tests complete");
  }

  private static class DatedElement {
    public long       date;
    public Object     key;
    public Object     val;
    public DatedElement(Object key, Object val) {
      this.key = key;
      this.val = val;
    }

    public void update() {
      date = System.currentTimeMillis();
    }
  }

  private class BackedKeySet extends AbstractSet {
    public BackedKeySet() {
    }

    public Iterator iterator() {
      return new KeyIterator();
    }

    public int size() {
      return _values.size();
    }

    public boolean remove(Object o) {
      DatedElement d = (DatedElement) _values.remove(o);
      if (d == null) {
        return false;
      }

      _dateSet.remove(d);
      return true;
    }
  }

  private class BackedEntrySet extends AbstractSet {
    public BackedEntrySet() {
    }

    public Iterator iterator() {
      return new EntryIterator();
    }

    public int size() {
      return _values.size();
    }
  }

  private class KeyIterator implements Iterator {
    private Iterator _iter    = _values.keySet().iterator();
    private Object   _lastObj = null;
    
    public KeyIterator() {}

    public boolean hasNext() {
      return _iter.hasNext();
    }

    public Object next() throws NoSuchElementException {
      _lastObj = _iter.next();
      DatedElement d = (DatedElement) _values.get(_lastObj);
      _dateSet.remove(d);
      d.update();
      _dateSet.add(d);
      checkErase(d.date);
      return _lastObj;
    }

    public void remove() 
      throws IllegalStateException, 
      UnsupportedOperationException {
      if (_lastObj != null) {
        DatedElement d = (DatedElement) _values.get(_lastObj);
        _iter.remove();
        if (d != null) {
          _dateSet.remove(d);
        } else {
          throw new IllegalStateException("Object already removed");
        }
      } else {
        throw new IllegalStateException("No element chosen");
      }
    }
  }

  private class MapEntry implements Map.Entry {
    private Object _key;
    private DatedElement _value;
    public MapEntry(Object key, DatedElement val) {
      _key = key;
      _value = val;
    }
    public boolean equals(Object o) {
      if (o instanceof Map.Entry) {
        Map.Entry m = (Map.Entry) o;
        if (_key == null && m.getKey() != null ||
            _value == null && m.getValue() != null) {
          return false;
        }
        return ((_key == null   || _key.equals(m.getKey())) &&
                (_value == null || _value.equals(m.getValue())));
      }
      return false;
    }
    
    public Object getKey() { return _key; }
    public Object getValue() { return _value.val; }
    public int hashCode() { return _key.hashCode(); }
    public Object setValue(Object val) { 
      _dateSet.remove(_value);
      _value.update();
      Object old = _value.val;
      _value.val = val;
      _dateSet.add(_value);
      return old;
    }
  }

  private class EntryIterator implements Iterator {
    private Iterator     _iter    = _values.entrySet().iterator();
    private DatedElement _lastObj = null;
    
    public EntryIterator() {}

    public boolean hasNext() {
      return _iter.hasNext();
    }

    public Object next() throws NoSuchElementException {
      Map.Entry entry = (Map.Entry) _iter.next();
      _lastObj = (DatedElement) entry.getValue();
      _dateSet.remove(_lastObj);
      _lastObj.update();
      _dateSet.add(_lastObj);
      checkErase(_lastObj.date);
      return new MapEntry(entry.getKey(), (DatedElement) entry.getValue());
    }

    public void remove() 
      throws IllegalStateException, 
      UnsupportedOperationException {
      if (_lastObj == null) {
        throw new IllegalStateException("No element chosen");
      } else {
        _iter.remove();
        _dateSet.remove(_lastObj);
      }
    }
  }

  private static class CompareDates implements Comparator {
    public int compare(Object o1, Object o2) {
      if (o1 == o2) {
        return 0;
      }
      DatedElement d1 = (DatedElement) o1;
      DatedElement d2 = (DatedElement) o2;
      long dcomp = d1.date-d2.date;
      if (dcomp > 0) return 1;
      if (dcomp < 0) return -1;
      return d1.hashCode() - d2.hashCode();
    }

    public boolean equals(Object obj) {
      return (obj instanceof CompareDates);
    }
  }
}

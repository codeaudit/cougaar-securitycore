

package org.cougaar.core.security.util;

import java.util.Map;
import java.util.HashMap;

/**
 * A HashMap that performs synchronization on individual key entries (as opposed to the
 * entire Map as does Hashtable).
 * This is particularly helpful when a get() operation takes a lot of time.
 */
public class ConcurrentHashMap extends HashMap {

  public Object get(Object keyEntry) {
    Object value = null;
    Marker marker = null;
    boolean wait = false;

    synchronized (this) {
      if (containsKey(keyEntry)) {
        if (! ((value = super.get(keyEntry)) instanceof Marker)) {
          System.out.println("Object already processed. " + keyEntry + " => " + value);
          return value;
        }
        else {
          // Another thread is already retrieving the value 
          // We should wait until the thread gets it.
          System.out.println("Object being processed by other thread. " + keyEntry);
          wait = true;
          marker = (Marker)value;
        }
      }
      else {
        System.out.println("Object not processed. " + keyEntry);
        marker = new Marker();
        put(keyEntry, marker);
      }
    }

    synchronized (marker) {
      if (wait) {
        synchronized (this) {
          if (! ((value = super.get(keyEntry)) instanceof Marker)) {
            System.out.println("Object already processed after wait. " + keyEntry + " => " + value);
            return value;
          }
        }
        System.out.println("Wait - Object being processed by other thread. " + keyEntry);
        try {
          System.out.println("Wait on " + marker);
          marker.wait();
        }
        catch (InterruptedException ex) {}
        System.out.println("Retrieved object after wait on " + marker);
        value = super.get(keyEntry);
        return value;
      }
      System.out.println("Retrieving object " + keyEntry);
      try {
        Thread.sleep(5 * 1000);
        System.out.println("");
      }
      catch (InterruptedException e) {};
      value = "myEntry value: " + keyEntry;
      synchronized(this) {
        put(keyEntry, value);
      }
      System.out.println("Retrieved object " + keyEntry + " => " + value);
      System.out.println("Notify threads on " + marker);
      marker.notifyAll();
    }
    return value;
  }


  private void testSerialAccess(String keyEntry) {
    for (int i = 0 ; i < 5 ; i++) {
      get(keyEntry);
    }
  }

  private void testConcurrentAccess(final String keyEntry) {
    for (int i = 0 ; i < 5 ; i++) {
      Runnable r = new Runnable() {
        public void run() {
           Object value = get(keyEntry);
           System.out.println("Got object " + keyEntry + " => " + value);
        }
      };
      Thread t = new Thread(r);
      t.start();
    }
  }

  public void testHashMap() {
    testSerialAccess("foo");
    System.out.println("");
    for (int i = 0 ; i < 5 ; i++) {
      testConcurrentAccess("foobar" + i);
    }
  }

  public static void main(String args[]) {
    ConcurrentHashMap hmt = new ConcurrentHashMap();
    hmt.testHashMap();
  }

  private class Marker {
  }
}

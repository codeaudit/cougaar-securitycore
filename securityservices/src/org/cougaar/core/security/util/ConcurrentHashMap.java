

package org.cougaar.core.security.util;

import java.util.Map;
import java.util.HashMap;

import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

/**
 * A HashMap that performs synchronization on individual key entries (as opposed to the
 * entire Map as does Hashtable).
 * This is particularly helpful when a get() operation takes a lot of time.
 */
public class ConcurrentHashMap extends HashMap {
  private static final Logger _logger =
  LoggerFactory.getInstance().createLogger(ConcurrentHashMap.class);

  public Object get(Object keyEntry, Get getter) throws Exception {
    Object value = null;
    Marker marker = null;
    boolean wait = false;

    synchronized (this) {
      if (containsKey(keyEntry)) {
        value = super.get(keyEntry);
        if (!(value instanceof MarkerException) && !(value instanceof Marker)) {
          if (_logger.isDebugEnabled()) {
            _logger.debug("Object already processed. " + keyEntry + " => " + value);
          }
          return value;
        }
        else if (value instanceof Marker) {
          // Another thread is already retrieving the value 
          // We should wait until the thread gets it.
          if (_logger.isDebugEnabled()) {
            _logger.debug("Object being processed by other thread. " + keyEntry);
          }
          wait = true;
          marker = (Marker)value;
        }
      }
      if (!wait) {
        if (_logger.isDebugEnabled()) {
          _logger.debug("Object not processed. " + keyEntry);
          if (value instanceof MarkerException) {
            _logger.debug("Object previously caused exception but retrying. " + keyEntry);
          }
        }
        marker = new Marker();
        put(keyEntry, marker);
      }
    }

    synchronized (marker) {
      if (wait) {
        synchronized (this) {
          if (! ((value = super.get(keyEntry)) instanceof Marker)) {
            if (_logger.isDebugEnabled()) {
              _logger.debug("Object already processed after wait. " + keyEntry + " => " + value);
            }
            if (value instanceof MarkerException) {
              throw new Exception ("Exception while processing object",
                ((MarkerException)value).getException());
            }
            return value;
          }
        }
        if (_logger.isDebugEnabled()) {
          _logger.debug("Wait - Object being processed by other thread. " + keyEntry);
        }
        try {
          if (_logger.isDebugEnabled()) {
            _logger.debug("Wait on " + marker);
          }
          marker.wait();
        }
        catch (InterruptedException ex) {}
        if (_logger.isDebugEnabled()) {
          _logger.debug("Retrieved object after wait on " + marker);
        }
        value = super.get(keyEntry);
        if (value instanceof MarkerException) {
          throw new Exception ("Exception while processing object",
              ((MarkerException)value).getException());
        }
        return value;
      }
      if (_logger.isDebugEnabled()) {
        _logger.debug("Retrieving object " + keyEntry);
      }
      Exception ex = null;
      try {
        value = getter.getValue(keyEntry);
        if (_logger.isDebugEnabled()) {
          _logger.debug("Retrieved object " + keyEntry + " => " + value);
        }
        synchronized(this) {
          put(keyEntry, value);
        }
      }
      catch (Exception e) {
        // Threads that wait on the exception should also throw an exception
        put(keyEntry, new MarkerException(e));
        throw e;
      }
      finally {
        if (_logger.isDebugEnabled()) {
          _logger.debug("Notify threads on " + marker);
        }
        marker.notifyAll();
      }
    }
    return value;
  }

  public static abstract class Get {
    public abstract Object getValue(Object key) throws Exception;
  }

  private void testSerialAccess(String keyEntry, ConcurrentHashMap.Get getter) {
    for (int i = 0 ; i < 5 ; i++) {
      try {
        get(keyEntry, getter);
      }
      catch (Exception e) {
        if (_logger.isWarnEnabled()) {
          _logger.warn("Unable to retrieve object" , e);
        }
      }
    }
  }

  private void testConcurrentAccess(final String keyEntry, final ConcurrentHashMap.Get getter) {
    for (int i = 0 ; i < 5 ; i++) {
      Runnable r = new Runnable() {
        public void run() {
           try {
             Object value = get(keyEntry, getter);
             if (_logger.isDebugEnabled()) {
               _logger.debug("Got object " + keyEntry + " => " + value);
             }
           }
           catch (Exception e) {
             if (_logger.isWarnEnabled()) {
               _logger.warn("Unable to retrieve object" , e);
             }
           }
        }
      };
      Thread t = new Thread(r);
      t.start();
    }
  }

  private void testException() {
  }

  public void testHashMap() {
    ConcurrentHashMap.Get getter1 = new ConcurrentHashMap.Get() {
      public Object getValue(Object keyEntry) {
        try {
          Thread.sleep(5 * 1000);
        }
        catch (InterruptedException e) {};
        return "myEntry value: " + keyEntry;
      }
    };

    // Test serial access
    testSerialAccess("foo", getter1);

    // Test concurrent access
    for (int i = 0 ; i < 1 ; i++) {
      testConcurrentAccess("foobar" + i, getter1);
    }

    // Test null values
    ConcurrentHashMap.Get getter2 = new ConcurrentHashMap.Get() {
      public Object getValue(Object keyEntry) {
        try {
          Thread.sleep(5 * 1000);
        }
        catch (InterruptedException e) {};
        return null;
      }
    };

    testSerialAccess("foonull", getter2);

    // Test concurrent access with exceptions
    ConcurrentHashMap.Get getter3 = new ConcurrentHashMap.Get() {
      public Object getValue(Object keyEntry) throws Exception {
        try {
          Thread.sleep(5 * 1000);
        }
        catch (InterruptedException e) {};
        throw new Exception ("Unable to retrieve object");
      }
    };
    for (int i = 0 ; i < 2 ; i++) {
      testConcurrentAccess("foofailure" + i, getter3);
    }

    // Wait a little bit, then try again with no failure
    if (_logger.isInfoEnabled()) {
      _logger.info("wait a little bit, then try again with no failure");
    }
    try {
      Thread.sleep(10 * 1000);
    }
    catch (Exception e) {}
    if (_logger.isInfoEnabled()) {
      _logger.info("Done waiting a little bit, try again with no failure");
    }
    for (int i = 0 ; i < 2 ; i++) {
      testConcurrentAccess("foofailure" + i, getter1);
    }
  }

  public static void main(String args[]) {
    ConcurrentHashMap hmt = new ConcurrentHashMap();
    hmt.testHashMap();
  }

  private class Marker {
  }
  private class MarkerException {
    private Exception theException;
    public MarkerException(Exception e) {
      theException = e;
    }
    public Exception getException() {
      return theException;
    }
  }
}

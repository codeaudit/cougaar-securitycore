
/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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
 * Created on September 12, 2001, 10:55 AM
 */

package test.org.cougaar.core.security.simul;

import org.apache.log4j.spi.RepositorySelector;
import org.apache.log4j.spi.LoggerRepository;
import org.apache.log4j.spi.RootCategory;
import org.apache.log4j.Hierarchy;
import org.apache.log4j.Level;
import java.util.Hashtable;

public class LogSelector
  implements RepositorySelector
{
  
  // key: current thread, 
  // value: Hierarchy instance
  private Hashtable ht;

  public LogSelector() {
   ht = new Hashtable(); 
  }

  // the returned value is guaranteed to be non-null
  public LoggerRepository getLoggerRepository() {
    Thread thread = Thread.currentThread();
    Hierarchy hierarchy = (Hierarchy) ht.get(thread);

    System.out.println("getLoggerRepository: " + thread.toString());
    /*
    try {
      throw new RuntimeException("sdf");
    }
    catch (Exception e) {
      e.printStackTrace();
    }
    */
    if(hierarchy == null) {
      System.out.println("getLoggerRepository: creating new repository");
      hierarchy = new Hierarchy(new RootCategory((Level) Level.DEBUG));
      ht.put(thread, hierarchy);
    } 
    return hierarchy;
  }

  /** 
   * The Container should remove the entry when the web-application
   * is removed or restarted.
   * */
  public void remove(Thread thread) {
    ht.remove(thread); 
  } 
}
      

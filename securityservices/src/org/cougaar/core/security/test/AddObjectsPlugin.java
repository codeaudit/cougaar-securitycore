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

package org.cougaar.core.security.test;

import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.LoggingService;

import java.io.Serializable;
import java.util.List;

/**
 * This class just adds some objects to the blackboard. 
 */
public class AddObjectsPlugin extends ComponentPlugin {

  private LoggingService  _log;
  private int             _maxObjects = 50000;
  private int             _objSize    = 1000;

  public void setParameter(Object o) {
    if (!(o instanceof List)) {
      throw new IllegalArgumentException("Expecting a List parameter " +
                                         "instead of " + 
                                         ( (o == null)
                                           ? "null" 
                                           : o.getClass().getName() ));
    }

    List l = (List) o;
    if (l.size() != 0) {
      _maxObjects = Integer.parseInt(l.remove(0).toString());
    } // end of if (l.size() != 0)
    if (l.size() != 0) {
      _objSize = Integer.parseInt(l.remove(0).toString());
    } // end of if (l.size() != 0)
  }

  protected void execute() {
  }

  /**
   * Sets up the AggregationQuery and event subscriptions.
   */
  protected void setupSubscriptions() {
    _log = (LoggingService)
	getServiceBroker().getService(this, LoggingService.class, null);

    System.out.println("adding objects to blackboard service");
    BlackboardService bbs = getBlackboardService();
    for (int i = 0; i < _maxObjects; i++) {
      bbs.publishAdd(new BigObject(_objSize));
      if (i % 1000 == 999) {
        System.out.println("Added " + (i+1) + " " + _objSize + " byte objects");
      }
    } // end of for (int i = 0; i < _maxObjects; i++)
    
  }

  private static class BigObject implements Serializable {
    byte buf[];
    public BigObject(int size) {
      buf = new byte[size];
      for (int i = 0; i < buf.length; i++) {
        buf[i] = (byte) i;
      } // end of for (int i = 0; i < buf.length; i++)
    }
  }
}

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

import java.util.Properties;

import javax.naming.Context;

import org.cougaar.bootstrap.SystemProperties;

public class TestProperties {
        
  public static void main(String[] args) {
    Properties props = System.getProperties();

    System.out.println("Context: " + Context.INITIAL_CONTEXT_FACTORY);
  
    props.list(System.out);
    
    System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++");
    /*
    for (Enumeration names = props.propertyNames(); names.hasMoreElements(); ) {
      String key = (String) names.nextElement();
      System.out.println("key:" + key);
    }
    */
    System.out.println("Props +++++++++++++++++++++++++++++++++++++++++++++++++++");
    props = SystemProperties.getStandardSystemProperties();
    System.out.println("Props +++++++++++++++++++++++++++++++++++++++++++++++++++");
    props.list(System.out);


    System.out.println("Props with prefix org.cougaar ++++++++++++++++++++++++++++");
    props = SystemProperties.getSystemPropertiesWithPrefix("org.cougaar");

    System.out.println("Props with prefix sun +++++++++++++++++++++++++++++++++++");
    props = SystemProperties.getSystemPropertiesWithPrefix("sun.");
  }
}

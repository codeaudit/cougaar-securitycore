/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Inc
 *  under sponsorship of the Defense Advanced Research Projects
 *  Agency (DARPA).
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 *
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 *
 * </copyright>
 *
 * CHANGE RECORD
 * -
 */

package org.cougaar.core.security.policy;

public class CryptoPolicy extends SecurityPolicy {
  private String InSecureMethod;
  private String InSymmSpec;
  private String InAsymmSpec;
  private String InSignSpec;
  private String OutSecureMethod;
  private String OutSymmSpec;
  private String OutAsymmSpec;
  private String OutSignSpec;

  public String getInSecureMethod() {  return InSecureMethod;   }
  public String getInSymmSpec() {      return InSymmSpec;    }
  public String getInAsymmSpec() {      return InAsymmSpec;    }
  public String getInSignSpec() {      return InSignSpec;    }
  public String getOutSecureMethod() {   return OutSecureMethod;    }
  public String getOutSymmSpec() {      return OutSymmSpec;    }
  public String getOutAsymmSpec() {      return OutAsymmSpec;    }
  public String getOutSignSpec() {      return OutSignSpec;    }

  public void setInSecureMethod(String ism){
    this.InSecureMethod = ism;   
  }
  public void setInAsymmSpec(String ias){
    this.InAsymmSpec = ias;   
  }
  public void setInSymmSpec(String iss){
    this.InSymmSpec = iss;   
  }
  public void setInSignSpec(String is){
    this.InSignSpec = is;   
  }
  public void setOutSecureMethod(String osm){
    this.OutSecureMethod = osm;   
  }
  public void setOutAsymmSpec(String oas){
    this.OutAsymmSpec = oas;   
  }
  public void setOutSymmSpec(String oss){
    this.OutSymmSpec = oss;   
  }
  public void setOutSignSpec(String os){
    this.OutSignSpec = os;   
  }

  public String toString() {
    return " InSecureMethod:" + InSecureMethod +
      " \nInAsymmSpec:" + InAsymmSpec +
      " \nInSymmSpec:" + InSymmSpec +
      " \nInSignSpec:" + InSignSpec +
      " \nOutSecureMethod:" + OutSecureMethod +
      " \nOutAsymmSpec:" + OutAsymmSpec +
      " \nOutSymmSpec:" + OutSymmSpec +
      " \nOutSignSpec:" + OutSignSpec;
  }
}

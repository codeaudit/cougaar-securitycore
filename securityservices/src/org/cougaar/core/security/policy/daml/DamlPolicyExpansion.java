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


package org.cougaar.core.security.policy.daml;

import safe.util.UnexpandedPolicyUpdate;
import java.util.List;

public class DamlPolicyExpansion {
  private int _expansionNum;
  private List _locators, _policies;
  private String _updateType;

  public DamlPolicyExpansion(String updateType, List locators, List policies,
                             int expansionNum) {
    _updateType = updateType;
    _locators = locators;
    _policies = policies;
    _expansionNum = expansionNum;
  }

  public String getUpdateType() { 
    return _updateType;
  }

  public List getLocators() {
    return _locators;
  }

  public List getPolicies() {
    return _policies;
  }

  public int getExpansionNum() {
    return _expansionNum;
  }

  public void setExpansionNum(int expansionNum) {
    _expansionNum = expansionNum;
  }
}


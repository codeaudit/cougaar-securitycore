/*
 * <copyright>
 *  Copyright 2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency *  (DARPA).
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

package org.cougaar.core.security.policy.builder;

import java.util.List;

public class ParsedTarget
{
  /*
   * A crufty point - I have just merged two very similar functionalities.
   * Range is now either a List or a String.  If it is a list then it
   * is a list of possible values for the property.  If it is a string
   * then it is a class of values for the property.  Most of the code is the
   * same in both cases but there is obviously some crud. 
   *
   */


  private String  _property;
  private String  _resType;
  private Object  _range;
  private boolean _isComplement;


  public ParsedTarget(String  property,
                      String  resType,
                      Object  range,
                      boolean isComplement)
  {
    _property     = property;
    _resType      = resType;
    _range        = range;
    _isComplement = isComplement;
    if (!((_range instanceof List) || (_range instanceof String))) {
      throw 
        new IllegalArgumentException("range should be a List or a String");
    }
  }


  public String getProperty()
  {
    return _property;
  }

  public String getRestrictionType()
  {
    return _resType;
  }

  public Object getRange()
  {
    return _range;
  }

  public boolean getIsComplement()
  { 
    return _isComplement;
  }
  


}

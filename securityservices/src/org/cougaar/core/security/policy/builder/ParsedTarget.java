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

/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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

package test.org.cougaar.core.security.simul;

import java.io.*;
import java.util.*;
import java.lang.reflect.*;

public class OperationConf
  implements Serializable
{
  private String className;
  private String methodName;
  private String argument;

  /** The type of this operation (before or after the test)
   */
  private int type;
  public static final int BEFORE = 1;
  public static final int AFTER = 2;

  public OperationConf(String type) {
    if (type.equals("before")) {
      this.type = BEFORE;
    }
    else if (type.equals("after")) {
      this.type = AFTER;
    }
    else {
      throw new RuntimeException("Illegal type: " + type);
    }
  }

  public int getType() {
    return type;
  }

  public void setClassName(String name) {
    className = name;
  }

  public void setMethodName(String name) {
    methodName = name;
  }
  public void setArgument(String args) {
    argument = args;
  }

  public Object invokeMethod(Object o)
    throws IllegalAccessException, InvocationTargetException,
    ClassNotFoundException, NoSuchMethodException {
    Method method = getMethod();
    if (method == null) {
      return null;
    }
    Object values[] = new Object[1];
    values[0] = argument;
    return method.invoke(o, values);
  }

  public Method getMethod()
    throws ClassNotFoundException, NoSuchMethodException {

    if (className == null || className.equals("")
	|| methodName == null || methodName.equals("")) {
      return null;
    }

    Class cl = Class.forName(className);
    Class parameterTypes[] = new Class[1];

    parameterTypes[0] = String.class;
    Method method = cl.getDeclaredMethod(methodName, parameterTypes);
    return method;
  }

  public String toString() {
    String s = "Type=";
    switch (type) {
    case BEFORE:
      s = s + "Pre-operation:";
      break;
    case AFTER:
      s = s + "Post-operation:";
      break;
    default:
      s = s + "Unknown operation:";
    }
    s = s + " Class name: " + className +
      " method: " + methodName + " arguments: "
      + argument;
    return s;
  }
}

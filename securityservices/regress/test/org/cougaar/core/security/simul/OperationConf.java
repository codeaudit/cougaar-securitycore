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
  /** An array of String. Methods can take a number of strings as their arguments. */
  private ArrayList arguments;
  private Class testClass;

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
    arguments = new ArrayList();
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
  public void addArgument(String args) {
    arguments.add(args);
  }

  public Object invokeMethod(Object o)
    throws IllegalAccessException, InvocationTargetException,
    ClassNotFoundException, NoSuchMethodException, InstantiationException {
    Method method = getMethod();
    if (method == null) {
      return null;
    }

    Object values[] = new Object[arguments.size()];
    for (int i = 0 ; i < arguments.size() ; i++) {
      values[i] = arguments.get(i);
    }
    if (o == null) {
      // Create a new class instance
      o = testClass.newInstance();
    }
    System.out.println("Invoking " + testClass.getName() + "." + methodName);
    return method.invoke(o, values);
  }

  public Method getMethod()
    throws ClassNotFoundException, NoSuchMethodException {

    if (className == null || className.equals("")
	|| methodName == null || methodName.equals("")) {
      return null;
    }

    testClass = Class.forName(className);
    Method ms[] = testClass.getDeclaredMethods();
    /*
    System.out.println(testClass.getName() + " declared methods:");
    for (int i = 0 ; i < ms.length ; i++) {
      System.out.println(ms[i]);
    }
    */
    Class parameterTypes[] = new Class[arguments.size()];
    for (int i = 0 ; i < arguments.size() ; i++) {
      parameterTypes[i] = String.class;
    }
    Method method = testClass.getDeclaredMethod(methodName, parameterTypes);
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
      " method: " + methodName + " arguments: ";
    for (int i = 0 ; i < arguments.size() ; i++) {
      s = s + arguments.get(i) + " ";
    }
    return s;
  }
}

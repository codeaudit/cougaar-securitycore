/**
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
 *
 * Created on September 27, 2001, 3:43 PM
 */

package org.cougaar.core.security.test;

import org.cougaar.core.security.provider.SecurityServiceProvider;

import java.lang.reflect.Method;

public class NodeSimul
{
  private SecurityServiceProvider secProvider = null;

  static public void main(String[] args){
    NodeSimul ns = new NodeSimul();

    System.out.println("Starting Node...");
    String[] launchArgs = new String[args.length - 1];
    System.arraycopy(args, 1, launchArgs, 0, launchArgs.length);
    ns.launch(args[0], launchArgs);
  }

  private void launch(String classname, String[] args) {
    //secProvider = new SecurityServiceProvider();
    //super.add(secProvider);

    try {
      Class realnode = Class.forName(classname);
      Class argl[] = new Class[1];
      argl[0] = String[].class;
      Method main;
      try {
        // try "launch" first
        main = realnode.getMethod("launch", argl);
      } catch (NoSuchMethodException nsm) {
        // if this one errors, we just let the exception throw up.
        main = realnode.getMethod("main", argl);
      }

      Object[] argv = new Object[1];
      argv[0] = args;

      Object theObject = realnode.newInstance();
      main.invoke(theObject, argv);
    } catch (Exception e) {
      System.err.println("Failed to launch "+classname+": ");
      e.printStackTrace();
    }
  }
}

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

package org.cougaar.core.security.test;

import java.io.*;
import java.net.*;
import java.util.*;
import java.text.*;

public class TestProcess
{
  private String environmentVariables[] = {
    "DISPLAY=localhost:0.0"
  };
  private File nodeStartupDirectory;
  //private String commandLine = "date";

  private String commandLine =
  "java -Dorg.cougaar.install.path=/home/u/srosset/UL/cougaar -Dorg.cougaar.core.persistence.enable=true -Dorg.cougaar.core.persistence.clear=true -Xbootclasspath/p:/home/u/srosset/UL/cougaar/lib/javaiopatch.jar -classpath /home/u/srosset/UL/cougaar/lib/CougaarCRLextensions.jar -Dorg.cougaar.config.path=\"/home/u/srosset/UL/cougaar/configs/security;\" -Xms64m -Xmx512m -Djava.rmi.server.hostname=tea -Duser.timezone=GMT -Dorg.cougaar.core.agent.startTime=08/10/2005 -Dorg.cougaar.planning.ldm.lps.ComplainingLP.level=0 -Dorg.cougaar.core.security.Domain=TestDomain -Dorg.cougaar.safe.domainName=TestDomain -Dorg.cougaar.core.naming.useSSL=true -Dorg.cougaar.lib.web.http.port=5561 -Dorg.cougaar.workspace=/home/u/srosset/UL/cougaar/workspace -Dorg.cougaar.core.security.bootstrap.keystore=/home/u/srosset/UL/cougaar/configs/security/bootstrap_keystore -Dorg.cougaar.core.logging.config.filename=loggingConfig.conf -Dorg.cougaar.core.logging.log4j.appender.SECURITY.File=/home/u/srosset/UL/cougaar/workspace/log4jlogs/caNode.log -Xbootclasspath/a:/home/u/srosset/UL/cougaar/lib/securebootstrapper.jar:/home/u/srosset/UL/cougaar/lib/bootstrap.jar -Dorg.cougaar.message.transport.aspects=org.cougaar.core.mts.StatisticsAspect,org.cougaar.core.mts.MessageProtectionAspect -Dorg.cougaar.lib.web.tomcat.enableAuth=true -Dorg.cougaar.security.role=srosset -Dorg.cougaar.bootstrap.class=org.cougaar.core.security.securebootstrap.SecureBootstrapper -Djava.security.policy=/home/u/srosset/UL/cougaar/configs/security/Cougaar_Java.policy -Dorg.cougaar.core.security.useSecurityManager=true -Dorg.cougaar.core.security.useAuthenticatedLoader=true -Dorg.cougaar.core.security.crypto.crlpoll=600 -Dorg.cougaar.security.crypto.config=cryptoPolicy.xml -Dorg.cougaar.core.security.crypto.debug=true -Dorg.cougaar.message.transport.debug=security  org.cougaar.bootstrap.Bootstrapper org.cougaar.core.node.Node -n caNode -c";

  public void start(String args[]) {
    Runtime thisApp = Runtime.getRuntime();
    Process nodeApp = null;
    nodeStartupDirectory = new File("./test/configs/cougaarCA");
    try {
      nodeApp = thisApp.exec(commandLine, environmentVariables, nodeStartupDirectory);
      System.out.println("Exit value: " + nodeApp.exitValue());
      BufferedInputStream nodeAppOut = new BufferedInputStream(nodeApp.getInputStream());
      BufferedInputStream nodeAppErr = new BufferedInputStream(nodeApp.getErrorStream());

      Thread.sleep(5000);
      byte buffer[] = new byte[2000];
      int bytes = 0;
      while (bytes != -1) {
	bytes = nodeAppErr.read(buffer, 0, buffer.length);
	System.out.println("StdErr: Reading " + bytes + " bytes");
	if (bytes > 0) {
	  String s = new String(buffer, 0, bytes);
	  System.err.print(s);
	}
      }

      bytes = 0;
      while (bytes != -1) {
	bytes = nodeAppOut.read(buffer, 0, buffer.length);
	System.out.println("StdOut: Reading " + bytes + " bytes");
	if (bytes > 0) {
	  String s = new String(buffer, 0, bytes);
	  System.out.print(s);
	}
      }
      nodeAppOut.close();
      nodeAppErr.close();
      nodeApp.waitFor();
    }
    catch (Exception e) {
      e.printStackTrace();
      System.out.println("Exception: " + e);
    }
 }

  public static void main(String args[]) {
    TestProcess tp = new TestProcess();
    tp.start(args);
  }
}

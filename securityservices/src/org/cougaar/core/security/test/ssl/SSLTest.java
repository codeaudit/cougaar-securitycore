/*
 * <copyright>
 *  Copyright 1997-2001 Network Associates
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
 */

package org.cougaar.core.security.test.ssl;

import java.net.*;
import java.io.*;

import javax.net.ssl.*;
import javax.net.*;

import javax.swing.*;

import org.cougaar.core.security.ssl.*;
import org.cougaar.core.security.userauth.*;
import org.cougaar.core.security.provider.*;
import org.cougaar.core.security.services.crypto.*;
import org.cougaar.core.security.crypto.*;
import org.cougaar.core.component.*;

public class SSLTest {
  SSLServiceImpl sslservice;
  SecurityServiceProvider secProvider;

  String host = "localhost";
  int port = 8080;

  public static void main(String[] args) {

    try {
      SSLTest test = new SSLTest();
      test.createService();

      //test.testSocket();

      test.testUserSocket();

      test.testPasswordAuth();
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public SSLTest() {
  }

  public void createService() throws Exception {
    secProvider = new SecurityServiceProvider();

    UserAuthenticatorImpl ua = new UserAuthenticatorImpl("test");
    ua.init(secProvider);
    ua.authenticateUser();

  }


  public void testSocket() {
    try {
      ServiceBroker serviceBroker = secProvider.getServiceBroker();
      KeyRingService keyRing = (KeyRingService)
                                        secProvider.getService(serviceBroker,
                                                       this,
                                                       KeyRingService.class);
      sslservice = new SSLServiceImpl();
      sslservice.init(keyRing);

      System.out.println("=====> Successfully created SSLService.");
    } catch (Exception e) {
      System.out.println("XXXXX SSLService exception occurred.");
      e.printStackTrace();
    }
    System.out.println("=====> Testing SSL client and server sockets.");
    try {
      ServerThread st = new ServerThread();
      st.start();

      SSLSocket s = (SSLSocket)KeyRingSSLFactory.getDefault().createSocket(host, port);

      System.out.println("=====> Testing send server stream.");

      OutputStream os = s.getOutputStream();
      PrintWriter writer = new PrintWriter(os);
      writer.println("Hello");
      writer.flush();
      writer.close();

      System.out.println("=====> Receiving server stream.");
      InputStream is = s.getInputStream();
      BufferedReader in = new BufferedReader(new InputStreamReader(is));
      while (in.ready()) {
        String text = in.readLine();
        System.out.println("=====> " + text);
      }
      s.close();

      System.out.println("======> Successfully tested sockets.");
    } catch (Exception ex) {
      System.out.println("XXXXX Exception occurred creating sockets.");
      ex.printStackTrace();
    }

  }

  public void testUserSocket() {
    System.out.println("=====> Testing usersocket");

    try {
      ServiceBroker serviceBroker = secProvider.getServiceBroker();
      UserSSLService userservice = (UserSSLService)
                                        secProvider.getService(serviceBroker,
                                                 this,
                                                 UserSSLService.class);
      SocketFactory usersocfac = userservice.getUserSocketFactory();
      String hostname = DirectoryKeyStore.getHostName();
      int hostport = 8400;
      System.out.println("Connecting to: " + hostname + " : " + hostport);
      //Socket s = usersocfac.createSocket(hostname, hostport);
      String path = "https://" + hostname + ":" + hostport + "/";
      URL url = new URL(path);
      BufferedReader in = new BufferedReader(
        new InputStreamReader(url.openStream()));
      String inputLine = "";
      while ((inputLine = in.readLine()) != null) {
        System.out.println(inputLine);
      }
      in.close();

      System.out.println("=====> Successfully created user socket.");
    } catch (Exception ex) {
      System.out.println("XXXXX Exception occurred: " + ex.toString());
      ex.printStackTrace();
    }
  }

  public void testPasswordAuth() {
    try {
      String path = JOptionPane.showInputDialog(
        "Enter the url to test: ");

      //HttpURLConnection.setDefaultAllowUserInteraction(true);
      URL url = new URL(path);
      BufferedReader in = new BufferedReader(
        new InputStreamReader(url.openStream()));
      String inputLine = "";
      while ((inputLine = in.readLine()) != null) {
        System.out.println(inputLine);
      }
      in.close();

    } catch (Exception ex) {
      System.out.println("XXXXX Exception occurred: " + ex.toString());
      ex.printStackTrace();
    }
  }

  class ServerThread extends Thread {

    public void run() {
      try {
        SSLServerSocket ss = (SSLServerSocket)
          KeyRingSSLServerFactory.getDefault().createServerSocket(port);
        SSLSocket s = (SSLSocket)ss.accept();
        //s.startHandshake();

        InputStream is = s.getInputStream();
        BufferedReader in = new BufferedReader(new InputStreamReader(is));
        StringBuffer textbuffer = new StringBuffer();
        while (in.ready()) {
          textbuffer.append(in.readLine());
        }

        System.out.println("Server received: " + textbuffer.toString());

        OutputStream out = s.getOutputStream();
        PrintWriter writer = new PrintWriter(out);
        writer.println(textbuffer.toString());
        writer.flush();
        writer.close();

        System.out.println("=====> Received socket request, responding.");

      } catch (Exception ex) {
        System.out.println("XXXXX Exception occurred creating server sockets.");
        ex.printStackTrace();
      }
    }
  }
}

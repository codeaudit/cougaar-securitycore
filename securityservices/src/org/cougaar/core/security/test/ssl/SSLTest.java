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


package org.cougaar.core.security.test.ssl;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.URL;

import javax.net.SocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.swing.JOptionPane;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.provider.SecurityServiceProvider;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.crypto.UserSSLService;
import org.cougaar.core.security.ssl.KeyRingSSLFactory;
import org.cougaar.core.security.ssl.KeyRingSSLServerFactory;
import org.cougaar.core.security.ssl.SSLServiceImpl;
import org.cougaar.core.security.userauth.UserAuthenticatorImpl;

public class SSLTest {
  private SSLServiceImpl sslservice;
  private SecurityServiceProvider secProvider;

  public static void main(String[] args) {

    try {
      SSLTest test = new SSLTest();

      String [] options = new String[4];
      options[0] = new String("All");
      options[1] = new String("SSL Socket");
      options[2] = new String("User SSL");
      options[3] = new String("Password authentication");

      int testid = JOptionPane.showOptionDialog(null, "Choose which test to perform", "SSL tests",
                    JOptionPane.DEFAULT_OPTION, JOptionPane.WARNING_MESSAGE,
                    null, options, options[0]);
      test.createService();

      if (testid == 0 || testid == 1)
        test.testSocket();

      if (testid == 0 || testid == 2)
        test.testUserSocket();

      if (testid == 0 || testid == 3)
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
                                        serviceBroker.getService(this,
								 KeyRingService.class,
								 null);
      sslservice = new SSLServiceImpl(serviceBroker);
      sslservice.init(keyRing);

      System.out.println("=====> Successfully created SSLService.");
    } catch (Exception e) {
      System.out.println("XXXXX SSLService exception occurred.");
      e.printStackTrace();
    }
    System.out.println("=====> Testing SSL client and server sockets.");
    try {
      String host = JOptionPane.showInputDialog(
        "Enter host to test: ");
      int port = Integer.parseInt(JOptionPane.showInputDialog(
        "Enter port to test: "));

      ServerThread st = new ServerThread(port);
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
                                        serviceBroker.getService(this,
								 UserSSLService.class,
								 null);
      SocketFactory usersocfac = userservice.getUserSocketFactory();
      //String hostname = DirectoryKeyStore.getHostName();
      //int hostport = 8400;
      //System.out.println("Connecting to: " + hostname + " : " + hostport);
      //Socket s = usersocfac.createSocket(hostname, hostport);
      //String path = "https://" + hostname + ":" + hostport + "/";
      String path = JOptionPane.showInputDialog(
        "Enter the url to test: ");
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
    int serverport = 0;

    ServerThread(int port) {
      serverport = port;
    }

    public void run() {
      try {
        SSLServerSocket ss = (SSLServerSocket)
          KeyRingSSLServerFactory.getDefault().createServerSocket(serverport);
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

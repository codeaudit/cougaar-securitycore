package org.cougaar.core.security.ssl;

import java.io.*;
import javax.net.ssl.*;
import java.net.*;
import java.security.*;
import javax.net.*;

// Cougaar core infrastructure
import org.cougaar.util.ConfigFinder;

// Cougaar security services
import com.nai.security.util.CryptoDebug;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.provider.SecurityServiceProvider;
import org.cougaar.core.security.services.crypto.KeyRingService;
import com.nai.security.crypto.*;
import org.cougaar.core.security.services.crypto.SSLService;

public final class SSLServiceImpl implements SSLService {
  // all singleton classes
  private static SSLServiceImpl sslservice = null;

  // may need to move to crypto policy file?
  private static final String SSLContextProtocol = "SSL";

  private static SSLContext sslcontext = null;
  private KeyManager km = null;
  private TrustManager tm = null;

  private SSLServiceImpl(KeyRingService krs)
    throws Exception
  {
    init(krs);
  }

  public synchronized static SSLServiceImpl getInstance(KeyRingService krs)
    throws Exception
  {
    if (sslservice != null)
      return sslservice;

    sslservice = new SSLServiceImpl(krs);
    return sslservice;
  }

  private synchronized void init(KeyRingService krs)
    throws Exception
  {
    if (sslservice != null)
      throw new Exception("Only one instance of SSLService should be created.");

    try {
      // create context
      SSLContext context = SSLContext.getInstance(SSLContextProtocol);

      // create keymanager and trust manager
      //DirectoryKeyStore ks = createDirectoryKeyStore();
      km = new KeyManager(krs);
      tm = new TrustManager(krs);

      context.init(new KeyManager[] {km}, new TrustManager[] {tm}, null);
      sslcontext = context;

      // set default connection socket factory
      HttpsURLConnection.setDefaultSSLSocketFactory(context.getSocketFactory());

      if (CryptoDebug.debug)
        System.out.println("Successfully created SSLContext.");

    } catch (Exception ex) {
      System.out.println("Exception when creating SSLContext.");
      ex.printStackTrace();
    }
  }

  /*
  public static DirectoryKeyStore createDirectoryKeyStore() {
    DirectoryKeyStore keystore = null;

    if (CryptoDebug.debug)
      System.out.println("createDirectoryKeyStore");

    // TODO. Modify following line to use service broker instead
    SecurityPropertiesService secprop = SecurityServiceProvider.getSecurityProperties(null);
    try {
      String installpath = secprop.getProperty(secprop.COUGAAR_INSTALL_PATH);

      // Keystore to store key pairs
      String defaultKeystorePath = installpath + File.separatorChar
	+ "configs" + File.separatorChar + "common"
	+ File.separatorChar + "keystore";
      DirectoryKeyStoreParameters param = new DirectoryKeyStoreParameters();
      param.keystorePassword =
	secprop.getProperty(secprop.KEYSTORE_PASSWORD,
			   "alpalp").toCharArray();
      param.keystorePath =
	secprop.getProperty(secprop.KEYSTORE_PATH,
			     defaultKeystorePath);
      File file = new File(param.keystorePath);
      if (!file.exists()){
	if (CryptoDebug.debug) {
	  System.out.println(param.keystorePath +
			     " keystore does not exist. Creating...");
	}
        KeyStore k = KeyStore.getInstance(KeyStore.getDefaultType());
        FileOutputStream fos = new FileOutputStream(param.keystorePath);
	k.load(null, param.keystorePassword);
        k.store(fos, param.keystorePassword);
	fos.close();

      }
      param.keystoreStream = new FileInputStream(param.keystorePath);
      param.isCertAuth = false;

      // CA keystore parameters
      ConfParser confParser = new ConfParser(null, param.isCertAuth);
      String role = secprop.getProperty(secprop.SECURITY_ROLE);
      if (role == null && CryptoDebug.debug == true) {
	System.out.println("Keyring Warning: LDAP role not defined");
      }
      NodePolicy nodePolicy = confParser.readNodePolicy(role);
      ConfigFinder configFinder = new ConfigFinder();
      File f = configFinder.locateFile(nodePolicy.CA_keystore);
      if (f != null) {
	param.caKeystorePath = f.getPath();
	param.caKeystorePassword = nodePolicy.CA_keystorePassword.toCharArray();
      }

      try {
	param.caKeystoreStream = new FileInputStream(param.caKeystorePath);
      }
      catch (Exception e) {
	if (CryptoDebug.debug) {
	  System.out.println("Could not open CA keystore: " + e);
	}
	param.caKeystoreStream = null;
	param.caKeystorePath = null;
	param.caKeystorePassword = null;
      }

      if (CryptoDebug.debug) {
	System.out.println("Secure message keystore: path="
			   + param.keystorePath);
	System.out.println("Secure message CA keystore: path="
			   + param.caKeystorePath);
      }

      // LDAP certificate directory
      param.ldapServerUrl = nodePolicy.certDirectoryUrl;
      param.ldapServerType = nodePolicy.certDirectoryType;

      keystore = new DirectoryKeyStore(param);

      if (param.keystoreStream != null) {
	param.keystoreStream.close();
      }
      if (param.caKeystoreStream != null) {
	param.caKeystoreStream.close();
      }

    } catch (Exception e) {
      e.printStackTrace();
    }
    return keystore;
  }
  */

  public void setUserCertificateCallback(UserCertificateUI userUI) {
    km.setUserCertificateUI(userUI);
  }

  public static SocketFactory getSocketFactory() {    
    //return sslcontext.getSocketFactory();
    if (sslcontext == null)
      return null;
    KeyRingSSLFactory.init(sslcontext);
    return (SSLSocketFactory)KeyRingSSLFactory.getDefault();
  }

  public static Socket createSocket(String host, int port) 
        throws IOException, UnknownHostException
  {
	return getSocketFactory().createSocket(host, port);
  }

  public static Socket getDefaultSocket(String host, int port) 
	throws IOException, UnknownHostException
  {
        return SSLSocketFactory.getDefault().createSocket(host, port);
  }

  public static ServerSocketFactory getServerSocketFactory() {
    //return sslcontext.getServerSocketFactory();
    if (sslcontext == null)
      return null;
    KeyRingSSLServerFactory.init(sslcontext);
    return (SSLServerSocketFactory)KeyRingSSLServerFactory.getDefault();
  }

  public static ServerSocket createServerSocket(int port) 
	throws IOException
  {
	return getServerSocketFactory().createServerSocket(port);
  }

  public static ServerSocket getDefaultServerSocket(int port) 
	throws IOException
  {
        return SSLServerSocketFactory.getDefault().createServerSocket(port);
  }
}

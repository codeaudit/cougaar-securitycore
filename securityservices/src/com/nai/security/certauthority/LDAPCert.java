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

package com.nai.security.certauthority;

import java.io.FileInputStream;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;

import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NameClassPair;
import javax.naming.NamingException;
import javax.naming.NamingEnumeration;

import javax.naming.ldap.LdapContext;
import javax.naming.ldap.InitialLdapContext;

import java.util.Hashtable;
import java.util.StringTokenizer;
import java.util.Vector;

import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.X509CRLEntry;
import java.security.Principal;

import java.text.SimpleDateFormat;

import com.nai.security.crypto.Base64;

public class LDAPCert //extends LdapContext
{
    protected static String CONTEXT_FACTORY = 
	"com.sun.jndi.ldap.LdapCtxFactory";
    protected static final String PEM_ATTRIBUTE = "pem_x509";
    //protected static final String PEM_ATTRIBUTE = "userCertificate";
    protected static final String UID_ATTRIBUTE = "md5";
    protected static final String CA_UID_ATTRIBUTE = "ca_md5";

    private static boolean debug = true;

    protected static DirContext ctx;
    protected static MessageDigest md5;

    protected String dn;
    protected Attributes set = new BasicAttributes(true);
    protected Attribute objectclass = new BasicAttribute("objectclass");
    protected String cn;
    
    protected X509Certificate cert = null;
    protected LdapEntry certEntry = null;
    protected String hash = null;

    protected static SimpleDateFormat day = new SimpleDateFormat("yyyyMMdd");
    protected static SimpleDateFormat time = new SimpleDateFormat("hhmmss");

    static {

	try {
	    md5 = MessageDigest.getInstance("MD5");
	}
	catch(Exception ex) {
	    ex.printStackTrace();
	}
    }

    public void setDebug(boolean flag) { debug = flag; }

    public void setDirContext(DirContext context) {
	ctx = context;
    }

    public void publish2Ldap(X509Certificate ca) {
	set = new BasicAttributes(true);
	objectclass = new BasicAttribute("objectclass");
	objectclass.add("xuda_certificate");
	objectclass.add("top");
	set.put(objectclass);	
	init(ca, ca);
	certEntry = new LdapEntry(cert, hash, "1");
	put();
    }

    public void publish2Ldap(X509Certificate client, X509Certificate signator)
    {
	set = new BasicAttributes(true);
	objectclass = new BasicAttribute("objectclass");
	objectclass.add("top");
	//objectclass.add("xuda_certificate");
	set.put(objectclass);	
	init(client, signator);
	put();
    }

    public Vector searchLdap() 
    {
	return getCertificates();
    }

    public static X509Certificate createCert(String pem) {
	X509Certificate cert = null;

	try {
	    InputStream inStream = 
		new ByteArrayInputStream(Base64.decode(pem.toCharArray()));
	    CertificateFactory cf = CertificateFactory.getInstance("X.509");
	    cert = (X509Certificate)cf.generateCertificate(inStream);
	    inStream.close();
	}
	catch(Exception ex) {
 	    if(debug)ex.printStackTrace();
	}
	return cert;
    }


    public static X509Certificate loadCert(String fileName) {
	X509Certificate cert = null;

	try {
	    InputStream inStream = new FileInputStream(fileName);
	    CertificateFactory cf = CertificateFactory.getInstance("X.509");
	    cert = (X509Certificate)cf.generateCertificate(inStream);
	    inStream.close();
	}
	catch(Exception ex) {
 	    if(debug)ex.printStackTrace();
	}
	return cert;
    }

    public LDAPCert() {
	this(System.getProperty("org.cougaar.security.ldap.url",
				"ldap://palm:389/"));
    }

    public LDAPCert(String url) 
    {
	Hashtable env = new Hashtable();
	
	env.put(Context.INITIAL_CONTEXT_FACTORY, CONTEXT_FACTORY);
	env.put(Context.PROVIDER_URL, url);
	env.put(Context.SECURITY_PRINCIPAL,"cn=manager,dc=cougaar,dc=org");
	env.put(Context.SECURITY_CREDENTIALS,"secret");
	if(debug) {
	    System.out.println(Context.INITIAL_CONTEXT_FACTORY + " = " + 
			       env.get(Context.INITIAL_CONTEXT_FACTORY));
	    System.out.println(Context.PROVIDER_URL + " = " + 
			       env.get(Context.PROVIDER_URL));
	}
	try {
	    ctx = new InitialDirContext(env);
	}
	catch(Exception ex) {
	    if(debug)ex.printStackTrace();
	}
    }

    //public LDAPCert(String filename) {
    //X509Certificate cert = loadCert(filename);
    //set = new BasicAttributes(true);
    //objectclass.add("xuda_ca");
    //set.put(objectclass);	
    //init(cert, cert);
    //}

    //public LDAPCert(X509Certificate cert) {
    //set = new BasicAttributes(true);
    //objectclass.add("xuda_ca");
    //set.put(objectclass);	
    //init(cert, cert);
    //}

    //public LDAPCert(String certFile, String caFile) {
    //X509Certificate cert = loadCert(certFile);
    //X509Certificate ca = loadCert(caFile);
    //set = new BasicAttributes(true);
    //objectclass.add("xuda_certifcate");
    //set.put(objectclass);	
    //init(cert, ca);
    //}

    public LDAPCert(X509Certificate cert, X509Certificate ca) {
	set = new BasicAttributes(true);
	objectclass.add("xuda_certificate");
	set.put(objectclass);	
	init(cert, ca);
    }
    
    protected String toHex(byte[] data) {
	StringBuffer buff = new StringBuffer();
	for(int i = 0; i < data.length; i++) {
	    String digit = Integer.toHexString(data[i] & 0x00ff);
	    if(digit.length() < 2)buff.append("0");
	    buff.append(digit);
	}
	return buff.toString();
    }

    protected byte[] hash(byte[] data, MessageDigest engine) {
	byte digest[];

	engine.reset();
	engine.update(data);
	digest = engine.digest();
	engine.reset();
	return digest;
    }

    protected void init(X509Certificate cert, X509Certificate issuer) {
	MessageDigest certDigest, issuerDigest;
	byte[] hash = null, ca_hash = null; // md & ca_md5 attribs for NetTools
	byte[] der = null, ca_der = null;   // der encoded certificates
	// Use the prefix of the signature algorithm for creating a DN
	String digestAlg = cert.getSigAlgName().substring(0,3);
	String caDigestAlg = issuer.getSigAlgName().substring(0,3);
	this.cert = cert;
	try { 
	    //certDigest = MessageDigest.getInstance("MD5");
	    //issuerDigest = MessageDigest.getInstance("MD5");
	    certDigest = MessageDigest.getInstance(digestAlg);
	    issuerDigest = MessageDigest.getInstance(caDigestAlg);
	    der = cert.getTBSCertificate();
	    ca_der = issuer.getTBSCertificate();
	}
	catch(Exception ex) {
	    if(debug)ex.printStackTrace();
	    return;
	}
	String pem = new String(Base64.encode(der));
	hash = hash(der, certDigest);
	ca_hash = hash(ca_der, issuerDigest);

	cn = "cn=" + toHex(hash);
        //dn = digestAlg.toLowerCase() + "=" +  toHex(hash);
	dn = cert.getSubjectDN().getName();
	//set.put("md5", toHex(hash));
	//set.put("ca_md5", toHex(ca_hash));
	set.put("serialNumber",
		cert.getSerialNumber().toString(16).toUpperCase());
	//set.put("notbefore_dte", day.format(cert.getNotBefore()));
	//set.put("notbefore_tim" , time.format(cert.getNotBefore()));
	//set.put("notafter_dte", day.format(cert.getNotAfter()));
	//set.put("notafter_tim" , time.format(cert.getNotAfter()));
	//set.put("cert_status", "1");
	//set.put(PEM_ATTRIBUTE, pem);
	parseDN(cert.getSubjectDN().getName(), set);
	if(debug) {
	    System.out.println("Loaded certificate with dn = " + dn);
	    //formatAttributes(set);
	}
    }

    public void parseDN(String dn, Attributes attribs) { 
	StringTokenizer parser = new StringTokenizer(dn, ",=");
	while(parser.hasMoreElements()) {
	    try {
		attribs.put(parser.nextToken().trim().toLowerCase(), 
			    parser.nextToken());
	    }
	    catch(Exception ex) {
		if(debug)ex.printStackTrace();
	    }
	}
    }

    /**
     * Generic method to format the Attributes. Displays all the multiple 
     * values of each Attribute in the Attributes. 
     */
    public  void formatAttributes(Attributes attrs) {
	if (attrs == null) {
	    return;
	} 
	try {
	    for (NamingEnumeration enum = attrs.getAll(); enum.hasMore();) {
		Attribute attrib = (Attribute)enum.next();
		System.out.print("ATTRIBUTE :" + attrib.getID());
		for (NamingEnumeration e = attrib.getAll();e.hasMore();)
		    System.out.println(" = " + e.next());
	    }
	    
	} catch (Exception e) {
	    e.printStackTrace();
	}
    }

    public Object removeObject(String cn) 
    {
	Object obj = null;
	try {
	    obj = ctx.lookup(cn); 
	    ctx.unbind(cn);
	}
	catch(NamingException ex) {
	    ex.printStackTrace();
	}
	return obj;
    }

    public LdapEntry getCertificate(String hash) 
    {
	NamingEnumeration results = null;
	Attributes set = null;
	X509Certificate cert;
	String status = null;

	//hash = (hash.startsWith("md5"))? hash: "md5=" + hash;	
	try {
	    set = ctx.getAttributes(hash);
	    cert = (X509Certificate)ctx.lookup(hash); 
	    //status = (String)set.get("cert_status").get();
	    //cert = createCert((String)set.get(PEM_ATTRIBUTE).get());
	    if(debug) {
		System.out.println("Retreived dn = " 
				   + cert.getSubjectDN().getName());
		//formatAttributes(set);
	}	}
	catch(Exception ex) {
	    ex.printStackTrace();
	    return null;
	}
	return new LdapEntry(cert, hash, status);
    } 


    public Vector getCertificates() {
	NamingEnumeration results = null;
	String name = null;
	Vector entries = new Vector();
	SearchControls controls = new SearchControls();
	String filter = "(objectclass=xuda_certificate)";
	BasicAttributes match = new BasicAttributes();
	BasicAttributes cert;

	controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
	objectclass = new BasicAttribute("objectclass");
	objectclass.add("xuda_certificate");
	match.put(objectclass);

	try {
	    System.out.println("ldap namespace = " + 
			       ctx.getNameInNamespace());
	    name = (String)ctx.getEnvironment().get(Context.PROVIDER_URL);
	    if(debug)System.out.println("name = " + name);
	    results = ctx.search(name, filter, controls);
	    results = ctx.list(name);
	    while(results.hasMoreElements()) {
		Object elm = results.nextElement();
		if(elm instanceof NameClassPair) {
		    NameClassPair pair = (NameClassPair)elm;
		    if(debug)System.out.println("Adding " + pair.getName() +
						" Class == " + pair.getClass());
		    formatAttributes(ctx.getAttributes(pair.getName()));
		    if(ctx.getAttributes(pair.getName()).get("objectClass").contains("top"))
			entries.add(getCertificate(pair.getName()));
		}
	    }
	}
	catch(Exception ex) {
	    if(debug)ex.printStackTrace();
	}
	return entries;
    }

    public void put() {
	try {
	    //ctx.createSubcontext(dn, set);
	    ctx.bind(cn, cert, set);
	}
	
	catch(Exception ex) {
	    ex.printStackTrace();
	}
    }
    
    public static void main(String arg[]) {
	LDAPCert lcert = 
	    new LDAPCert((arg.length > 1)? arg[1]: "ldap://yew:389/");
	try {
	    if(arg[0].equals("list") )
		lcert.getCertificates();
	    else if(arg[0].equals("put")) {
		X509Certificate cert = loadCert(arg[2]);
		X509Certificate ca = loadCert(arg[3]);
		lcert.publish2Ldap(cert, ca);
	    }
	    else if(arg[0].equals("search")) {
		lcert.getCertificate(arg[1]);
	    }
	    else if(arg[0].equals("remove")) {
		lcert.removeObject(arg[2]);
	    }
	}
	catch(Exception ex) {
	    if(debug)ex.printStackTrace();
	}

    }

  void publishCRLentry(X509CRLEntry crlEntry) {
      //certEntry = new LdapEntry(cert, hash, "1");
      //put();
  }
}

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
import java.math.BigInteger;

import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.naming.NamingEnumeration;

import javax.naming.ldap.LdapContext;
import javax.naming.ldap.InitialLdapContext;

import java.util.Hashtable;
import java.util.StringTokenizer;

import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.Principal;

import java.text.SimpleDateFormat;

import com.nai.security.crypto.Base64;

    public class LDAPCert //extends LdapContext
{
    protected static String CONTEXT_FACTORY = 
	"com.sun.jndi.ldap.LdapCtxFactory";

    private static boolean debug = true;

    protected static DirContext ctx;
    protected static MessageDigest md5;

    protected String dn;
    protected Attributes set = new BasicAttributes(true);
    protected Attribute objectclass = new BasicAttribute("objectclass");
    protected Attribute ouSet = new BasicAttribute("ou");
    
    protected X509Certificate cert;
    
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

    public void pulish2Ldap(X509Certificate ca) {
	set = new BasicAttributes(true);
	objectclass = new BasicAttribute("objectclass");
	objectclass.add("xuda_certifcate");
	set.put(objectclass);	
	init(ca, ca);
    }

    public void publish2Ldap(X509Certificate client, X509Certificate signator)
    {
	set = new BasicAttributes(true);
	objectclass = new BasicAttribute("objectclass");
	objectclass.add("xuda_certifcate");
	set.put(objectclass);	
	init(client, signator);
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

    public LDAPCert(String filename) {
	X509Certificate cert = loadCert(filename);
	set = new BasicAttributes(true);
	objectclass.add("xuda_ca");
	set.put(objectclass);	
	init(cert, cert);
    }

    public LDAPCert(X509Certificate cert) {
	set = new BasicAttributes(true);
	objectclass.add("xuda_ca");
	set.put(objectclass);	
	init(cert, cert);
    }

    public LDAPCert(String certFile, String caFile) {
	X509Certificate cert = loadCert(certFile);
	X509Certificate ca = loadCert(caFile);
	set = new BasicAttributes(true);
	objectclass.add("xuda_certifcate");
	set.put(objectclass);	
	init(cert, ca);
    }

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

        dn = digestAlg.toLowerCase() + "=" +  toHex(hash);
	set.put("md5", toHex(hash));
	set.put("ca_md5", toHex(ca_hash));
	set.put("serial_no",
		cert.getSerialNumber().toString(16).toUpperCase());
	set.put("notbefore_dte", day.format(cert.getNotBefore()));
	set.put("notbefore_tim" , time.format(cert.getNotBefore()));
	set.put("notafter_dte", day.format(cert.getNotAfter()));
	set.put("notafter_tim" , time.format(cert.getNotAfter()));
	set.put("cert_status", "1");
	set.put("pem_x509", pem);
	parseDN(cert.getIssuerDN().getName(), set);
	if(debug) {
	    System.out.println("Loaded certificate with dn = " + dn);
	    formatAttributes(set);
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


    public void put() {
	try {
	    ctx.createSubcontext(dn, set);
	}
	catch(Exception ex) {
	    ex.printStackTrace();
	}
    }
    
    public static void main(String arg[]) {
	LDAPCert lcert;
	Hashtable env = new Hashtable();

	env.put(Context.INITIAL_CONTEXT_FACTORY, CONTEXT_FACTORY);
	env.put(Context.PROVIDER_URL, "ldap://palm:389/");
	
	switch(arg.length) {
	case 0:  return;
	case 1:  lcert = new LDAPCert(arg[0]);
	         break;
	default: env.put(Context.PROVIDER_URL, "ldap://palm:389/");
	case 2:  lcert = new LDAPCert(arg[0], arg[1]);
	}
	
	System.out.println("Using certificate file = " + arg[0]);
	if(debug)System.out.println("Initial context is " + 
				    env.get(Context.PROVIDER_URL));
	try {
	    lcert.setDirContext(new InitialDirContext(env));
	    //lcert.put(); 
	}
	catch(Exception ex) {
	    if(debug)ex.printStackTrace();
	}

    }
}

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

//package com.nai.security.certauthority;

import java.io.FileInputStream;
import java.io.InputStream;

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

import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import java.text.SimpleDateFormat;

import com.nai.security.crypto.Base64;

    public class LDAPCert //extends LdapContext
{
    protected static String CONTEXT_FACTORY = 
	"com.sun.jndi.ldap.LdapCtxFactory";

    private static boolean debug = true;

    protected static DirContext ctx;
    protected String dn;
    protected Attributes set = new BasicAttributes(true);
    protected Attribute objectclass = new BasicAttribute("objectclass");
    protected Attribute ouSet = new BasicAttribute("ou");
    
    protected X509Certificate cert;
    protected static MessageDigest md5;

    protected static SimpleDateFormat day = new SimpleDateFormat("yyyyMMdd");
    protected static SimpleDateFormat time = new SimpleDateFormat("hhmmss");

    static {
	try {
	    md5 = MessageDigest.getInstance("MD5");
	}
	catch(Exception ex) {
	    if(debug)ex.printStackTrace();
	}
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
	
	if(debug) {
	    System.out.println("Serial no. = " +  cert.getSerialNumber());
	    System.out.println("notbefore_dte="+day.format(cert.getNotBefore()));
	    System.out.println("notbefore_tim" +time.format(cert.getNotBefore()));
	    System.out.println("notafter_dte="+day.format(cert.getNotAfter()));
	    System.out.println("notafter_tim" +time.format(cert.getNotAfter()));
	}
    }

    protected byte[] md5hash(byte[] data) {
	byte digest[];

	md5.reset();
	md5.update(data);
	digest = md5.digest();
	md5.reset();
	return digest;
    }

    public void init(X509Certificate cert, X509Certificate issuer) {
	String md5hash;

	try { 
	    md5hash = new String(Base64.encode(md5hash(cert.getEncoded())));
	}
	catch(Exception ex) {
	    if(debug)ex.printStackTrace();
	}

	objectclass.add("xuda_certificate");
	dn = "md5=" + 
	set.put("md5", "md5");
	set.put("ca_md5", "md5");
	set.put("serial_no", "md5");
	set.put("cn", "Foo");
	set.put("Serial no. = ", cert.getSerialNumber());
	set.put("notbefore_dte=", day.format(cert.getNotBefore()));
	set.put("notbefore_tim" , time.format(cert.getNotBefore()));
	set.put("notafter_dte=", day.format(cert.getNotAfter()));
	set.put("notafter_tim" , time.format(cert.getNotAfter()));
    }

    public void put() { }

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
		System.out.println("ATTRIBUTE :" + attrib.getID());
		for (NamingEnumeration e = attrib.getAll();e.hasMore();)
		    System.out.println("\t\t = " + e.next());
	    }
	    
	} catch (Exception e) {
	    e.printStackTrace();
	}
    }



    
    public static void main(String arg[]) {
	System.out.println("Using certificate file = " + arg[0]);
	LDAPCert lcert = new LDAPCert(arg[0]);

	
	Hashtable env = new Hashtable();
	env.put(Context.INITIAL_CONTEXT_FACTORY, CONTEXT_FACTORY);
	env.put(Context.PROVIDER_URL, "ldap://palm:389/");
	//else 
	//env.put(Context.PROVIDER_URL, arg[0]);
	
	if(debug)System.out.println("Initial context is " + 
				    env.get(Context.PROVIDER_URL));
	try {
	    ctx = new InitialDirContext(env);
	    //ctx.search("*", 
	}
	catch(Exception ex) {
	    if(debug)ex.printStackTrace();
	}

    }
}

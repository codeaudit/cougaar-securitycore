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

import java.io.*;
import java.net.*;
import java.util.*;
import java.security.cert.*;
import java.security.*;
import sun.security.pkcs.*;
import sun.security.x509.*;
import sun.security.util.*;

import com.nai.security.crypto.*;

public class KeyManagement
{
  private static boolean debug = false;

	

	public KeyManagement() {
	}

	public void signCertificate(byte request[]) {
			}

	public static void main(String[] args) {
		BufferedReader pkcs10stream = null;
		String pkcs10filename = args[0];
		PKCS10 pkcs10Request = null;
		PrintStream dbgout = new PrintStream(System.out);

		System.out.println("PKCS10 file: " + pkcs10filename);
		try {
			FileReader fr = new FileReader(pkcs10filename);
			pkcs10stream = new BufferedReader(fr);
		} catch (FileNotFoundException e) {
			System.out.println("File not found");
			return;
		}
		char pkcs10req[] = new char[1000];

		try {
			int offset = 0;
			while (pkcs10stream.ready()) {
				offset += pkcs10stream.read(pkcs10req, offset, 256);
			}
		} catch (IOException e) {
			System.out.println("read - IOException");
		}

		String pkcs10Header = "-----BEGIN NEW CERTIFICATE REQUEST-----";
		String pkcs10Trailer = "-----END NEW CERTIFICATE REQUEST-----";
		String s = new String(pkcs10req);

		byte derReq[] = new byte[0];

		if (s.startsWith(pkcs10Header)) {
			// This is a Base64 encoded PKCS10 request.
			System.out.println("Base64 encoded");
			String req = s.substring(pkcs10Header.length(), s.indexOf(pkcs10Trailer));
			derReq = Base64.decode(req.toCharArray());
		}
		else {
			// This is a DER encoded PKCS10 request.
			System.out.println("DER encoded");
			for (int i = 0 ; i < pkcs10req.length ; i++) {
				derReq[i] = (byte) pkcs10req[i];
			}
		}
		System.out.println("PKCS10 Request:" + new String(Base64.encode(derReq)));
		try {
			pkcs10Request = new PKCS10(derReq);
		} catch (IOException e) {
			System.out.println("IOException");
		} catch (SignatureException e) {
			System.out.println("SignatureException");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("NoSuchAlgorithmException");
		}

		System.out.println(pkcs10Request.toString());
		try {
			pkcs10Request.print(dbgout);
		} catch (IOException e) {
		} catch (SignatureException e) {
		}

		String CAalias = "bootstrapper";
		PrivateKey pk = KeyRing.getPrivateKey(CAalias);
		Signature se = null;
		String spec;
		spec=pk.getAlgorithm();
		try {
			se = Signature.getInstance(spec);
		} catch (NoSuchAlgorithmException e) {
		System.out.println("NoSuchAlgorithmException");
		}

		DerValue caDER = null;
		try {
			caDER = new DerValue(pk.getEncoded());
		} catch (IOException e) {
			System.out.println("IOException");
		}
		X500Name signerName = null;
		try {
			signerName = new X500Name(caDER);
		} catch (IOException e) {
			System.out.println("IOException");
		}

		X500Signer signer = new X500Signer(se, signerName);
		try {
			pkcs10Request.encodeAndSign(signer);
		}
		catch (CertificateException e) {
		} catch (IOException e) {
		} catch (SignatureException e) {
		}
	}
}



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

import java.security.cert.X509Certificate;
import java.io.Serializable;

/**
 * A bean which represent a certificate entry in the LDAP server.
 */
public class LdapEntry implements Serializable{
    private X509Certificate cert;
    private String status;
    private String hash;

    public LdapEntry(X509Certificate cert, String hash, String status) 
    {
	this.cert = cert;
	this.hash = hash;
	this.status = status;
    }

    /** 
     * Public accessor method for retrieving the actual certificate.
     */
    public X509Certificate getCertificate() { return cert; }

    /**
     * Public accessor method for retrieving the status of a certificate,
     * where 1 means valid, 2 means ???, and  3 means revoked
     */
    public String getStatus() { return status; }

    /**
     * Public accessor method for retrieving the unique hash used for indexing
     * by the LDAP server.
     */
    public String getHash() { return hash; }

    /**
     * Public modifier method for changing the hash value.
     */
    //public void setHash(String hash) { this.hash = hash; }

    /** 
     * Public modifier method for changing the status of this certificate
     * entry in the LDAP server.
     */
    public void setStatus(String status) { this.status = status; }

    /**
     * Public modifier methof for changing the certificate object itself.
     */
    public void setCert(X509Certificate cert) { this.cert = cert; }

}

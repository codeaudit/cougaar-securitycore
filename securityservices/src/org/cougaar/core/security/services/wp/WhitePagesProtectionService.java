/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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


package org.cougaar.core.security.services.wp;


import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;

import org.cougaar.core.component.Service;
import org.cougaar.core.service.wp.Request;


/**
 * Service for WP servers and clients to user for protecting and verifying  WP
 * requests
 *
 * @author mabrams
 */
public interface WhitePagesProtectionService extends Service {
    /**
     * Signs the request and wraps the request with the certificate chain used
     * for signing
     *
     * @param agent - The agent making the request
     * @param request - the request object
     *
     * @return the wraped request object
     */
    public ProtectedRequest protectRequest(String agent, Request request)
        throws CertificateException, GeneralSecurityException;


    /**
     * Installs and verifies the signing certificate
     *
     * @param agent - The agent making the request
     * @param request - the request object
     */
    public void verfifyRequest(String agent, ProtectedRequest request)
        throws CertificateException;
}

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


package org.cougaar.core.security.cm;


import java.io.Serializable;


/**
 * Conifiguration Manager Message
 * 	Request and Response are both in the Message so 
 *  the calling component can easily match request
 *  to response.
 *
 * @author ttschampel
 * @version $Revision: 1.1 $
 */
public class CMMessage implements Serializable {
  private CMRequest request;
  private CMResponse response;

  /**
   * Get Request
   *
   * @return
   */
  public CMRequest getRequest() {
    return request;
  }


  /**
   * Set Request
   *
   * @param request
   */
  public void setRequest(CMRequest request) {
    this.request = request;
  }


  /**
   * Set Response
   *
   * @return
   */
  public CMResponse getResponse() {
    return response;
  }


  /**
   * Get Response
   *
   * @param response
   */
  void setResponse(CMResponse response) {
    this.response = response;
  }

  /**
   * CMRequest interface
   *
   * @author ttschampel
   */
  public interface CMRequest {
  }


  /**
   * CM Response Interface
   *
   * @author ttschampel
   */
  public interface CMResponse {
  }
}

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
 

package org.cougaar.core.security.cm.message;


import java.io.Serializable;

import org.cougaar.core.security.cm.CMMessage.CMResponse;


/**
 * A simple true of false response verifying that a CMRequest
 * 	is valid.
 *
 * @version $Revision: 1.2 $
 * @author ttschampel
 */
public class VerifyResponse implements CMResponse, Serializable {
  private boolean validRequest;

  /**
   * Creates a new VerifyResponse object.
   *
   * @param valid If response if valid
   */
  public VerifyResponse(boolean valid) {
    this.validRequest = valid;

  }

  /**
   * Get the validity of the Configuration Manager Message's Request.
   *
   * @return validRequest
   */
  public boolean getValidRequest() {
    return validRequest;
  }
}

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

package org.cougaar.security.mop.ethereal;

/**
 * This class contains various statistics about a network protocol.
 */
public class ProtocolStatistics
{
  /** The name of the protocol.
   */
  private String _protocolName;

  /** Number of frames for this protocol.
   */
  private long _frames;

  /** Number of bytes for this protocol.
   */
  private long _bytes;

  public ProtocolStatistics(String protocolName,
			    long frames, long bytes) {
    _protocolName = protocolName;
    _frames = frames;
    _bytes = bytes;
  }

  public String getProtocolName() {
    return _protocolName;
  }

  public long getFrames() {
    return _frames;
  }
  public void setFrames(long frames) {
    _frames = frames;
  }

  public long getBytes() {
    return _bytes;
  }
  public void setBytes(long bytes) {
    _bytes = bytes;
  }

  public String toString() {
    return _protocolName;
  }

  public String getDetails() {
    return "Name: " + _protocolName + "\n"
      + "Frames: " + _frames + "\n"
      + "Bytes: " + _bytes;
  }
}

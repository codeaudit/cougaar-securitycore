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

  /** A dot-separated list of protocol names from the root
   */
  private String _protocolPath;

  /** Number of frames for this protocol, including lower-level protocols
   */
  private Long _totalFrames;

  /** Number of frames for this protocol only
   */
  private Long _frames;

  /** Number of bytes for this protocol, including lower-level protocols
   */
  private Long _totalBytes;

  /** Number of bytes for this protocol only
   */
  private Long _bytes;

  /** The policy associated with this protocol.
   */
  private ProtocolPolicy _protocolPolicy;

  public ProtocolStatistics(String protocolName,
			    Long totalframes, Long totalbytes) {
    _protocolName = protocolName;
    _totalFrames = totalframes;
    _totalBytes = totalbytes;
    
    // The bytes and frames are not available initially. We compute them as
    // we add objects in the tree.
    _bytes = _totalBytes;
    _frames = _totalFrames;
  }

  public void setProtocolPolicy(ProtocolPolicy pp) { _protocolPolicy = pp; }
  public ProtocolPolicy getProtocolPolicy() { return _protocolPolicy; }

  public String getProtocolName() { return _protocolName; }

  public String getProtocolPath() { return _protocolPath; }
  public void setProtocolPath(String path) { _protocolPath = path; }

  public Long getFrames() { return _frames; }
  public void setFrames(Long frames) { _frames = frames; }

  public Long getTotalFrames() { return _totalFrames; }
  public void setTotalFrames(Long frames) { _totalFrames = frames; }

  public Long getBytes() { return _bytes; }
  public void setBytes(Long bytes) { _bytes = bytes; }

  public Long getTotalBytes() { return _totalBytes; }
  public void setTotalBytes(Long bytes) { _totalBytes = bytes; }

  public String toString() {
    return _protocolName;
  }

  public String getDetails() {
    String s = "Name: " + _protocolPath + "\n"
      + "Total frames: " + _totalFrames + " - Total Bytes: " + _totalBytes + "\n"
      + "Frames: " + _frames + " - Bytes: " + _bytes + "\n";

    if (_protocolPolicy != null) {
      if (_protocolPolicy.isEncrypted() == Boolean.TRUE) {
	s = s + "Encrypted";
      }
      else if (_protocolPolicy.isEncrypted() == Boolean.FALSE) {
	s = s + "Unencrypted";
      }
      else {
	s = s + "Unknown protection";
      }
      s = s + " - ";
      
      if (_protocolPolicy.isOk() == Boolean.TRUE) {
	s = s + "OK";
      }
      else if (_protocolPolicy.isOk() == Boolean.FALSE) {
	s = s + "Unexpected";
      }
      else {
	s = s + "Unknown";
      }
    }
    return s;
  }
}

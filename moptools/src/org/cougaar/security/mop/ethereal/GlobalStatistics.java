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

public class GlobalStatistics {
  /** The sum of encrypted bytes and frames
   */
  private long _totalEncryptedBytes;
  private long _totalEncryptedFrames;

  /** The sum of unencrypted bytes and frames
   */
  private long _totalUnencryptedBytes;
  private long _totalUnencryptedFrames;

  /** The sum of unencrypted bytes and frames that should have been encrypted.
   */
  private long _totalUnexpectedUnencryptedBytes;
  private long _totalUnexpectedUnencryptedFrames;

  /** The sum of bytes and frames.
   */
  private long _totalBytes;
  private long _totalFrames;

  /** MOP total bytes and frames.
   */
  private long _totalMopBytes;
  private long _totalMopFrames;

  private void updateMopValues() {
    _totalMopBytes = _totalEncryptedBytes + _totalUnexpectedUnencryptedBytes;
    _totalMopFrames = _totalEncryptedFrames + _totalUnexpectedUnencryptedFrames;
  }

  public long getTotalBytes() { return _totalBytes; }
  public void setTotalBytes(long v) { _totalBytes = v; }

  public long getTotalEncryptedBytes() { return _totalEncryptedBytes; }
  public void setTotalEncryptedBytes(long v) {
    _totalEncryptedBytes = v;
    updateMopValues();
  }

  public long getTotalUnencryptedBytes() { return _totalUnencryptedBytes; }
  public void setTotalUnencryptedBytes(long v) { _totalUnencryptedBytes = v; }
  public long getTotalUnexpectedUnencryptedBytes() { return _totalUnexpectedUnencryptedBytes; }
  public void setTotalUnexpectedUnencryptedBytes(long v) {
    _totalUnexpectedUnencryptedBytes = v;
    updateMopValues();
  }

  public long getTotalFrames() { return _totalFrames; }
  public void setTotalFrames(long v) { _totalFrames = v; }

  public long getTotalEncryptedFrames() { return _totalEncryptedFrames; }
  public void setTotalEncryptedFrames(long v) {
    _totalEncryptedFrames = v;
    updateMopValues();
  }

  public long getTotalUnencryptedFrames() { return _totalUnencryptedFrames; }
  public void setTotalUnencryptedFrames(long v) { _totalUnencryptedFrames = v; }
  public long getTotalUnexpectedUnencryptedFrames() { return _totalUnexpectedUnencryptedFrames; }
  public void setTotalUnexpectedUnencryptedFrames(long v) {
    _totalUnexpectedUnencryptedFrames = v;
    updateMopValues();
  }

  public String toHtml() {

    String s = "<html><body>"
      + "<b>Global statistics:</b><br>" +
      "Encrypted bytes: " + _totalEncryptedBytes +
      " (" + getRatio(_totalEncryptedBytes, _totalBytes) + "%)" + 
      " - Unencrypted bytes: " + _totalUnencryptedBytes +
      " (" + getRatio(_totalUnencryptedBytes, _totalBytes) + "%)" + 
      " - Total bytes: " + _totalBytes + "<br>" +

      "Encrypted frames: " + _totalEncryptedFrames +
      " ("  + getRatio(_totalEncryptedFrames, _totalFrames) + "%)" + 
      " - Unencrypted frames: " + _totalUnencryptedFrames +
      " ("  + getRatio(_totalUnencryptedFrames, _totalFrames) + "%)" + 
      " - Total frames: " + _totalFrames +

      "<br><b>MOP statistics:</b><br>" +
      "Encrypted bytes: " + _totalEncryptedBytes +
      " (" + getRatio(_totalEncryptedBytes, _totalMopBytes) + "%)" + 
      " - Unexpected clear-text bytes: " + _totalUnexpectedUnencryptedBytes +
      " (" + getRatio(_totalUnexpectedUnencryptedBytes, _totalMopBytes) + "%)" + 
      " - Total MOP bytes: " + _totalMopBytes + "<br>" +

     "Encrypted frames: " + _totalEncryptedFrames +
      " ("  + getRatio(_totalEncryptedFrames, _totalMopFrames) + "%)" + 
      " - Unencrypted frames: " + _totalUnexpectedUnencryptedFrames +
      " ("  + getRatio(_totalUnexpectedUnencryptedFrames, _totalMopFrames) + "%)" + 
      " - Total frames: " + _totalMopFrames +

      "</body></html>";
    return s;
  }

  private double getRatio(long value, long total) {
    return (double)Math.round((((double)value / total)) * 10000) / 100;
  }
}

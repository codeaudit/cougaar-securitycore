/*
 * @(#)ByteArrayOutputStream.java	1.46 03/01/23
 *
 * Copyright 2003 Sun Microsystems, Inc. All rights reserved.
 * SUN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */

package java.io;


/**
 * This class implements an output stream in which the data is 
 * written into a byte array. The buffer automatically grows as data 
 * is written to it. 
 * The data can be retrieved using <code>toByteArray()</code> and
 * <code>toString()</code>.
 * <p>
 * Closing a <tt>ByteArrayOutputStream</tt> has no effect. The methods in
 * this class can be called after the stream has been closed without
 * generating an <tt>IOException</tt>.
 *
 * @author  Arthur van Hoff
 * @version 1.46, 01/23/03
 * @since   JDK1.0
 */

import java.util.*;
import java.lang.ref.*;

public class ByteArrayOutputStream extends OutputStream {

    public static long combinedCount;
    public static long combinedCapacity;
    public static long byteArrays;
    public static long liveByteArrays;
    public static long byteArraysGCed;
    private static Map arrays = new WeakHashMap();

    /** 
     * The buffer where data is stored. 
     */
    protected byte buf[];

    /**
     * The number of valid bytes in the buffer. 
     */
    protected int count;

    /**
     * Creates a new byte array output stream. The buffer capacity is 
     * initially 32 bytes, though its size increases if necessary. 
     */
    public ByteArrayOutputStream() {
	this(32);
    }

    /**
     * Creates a new byte array output stream, with a buffer capacity of 
     * the specified size, in bytes. 
     *
     * @param   size   the initial size.
     * @exception  IllegalArgumentException if size is negative.
     */
    public ByteArrayOutputStream(int size) {
        if (size < 0) {
            throw new IllegalArgumentException("Negative initial size: "
                                               + size);
        }

	buf = new byte[size];

        synchronized(arrays) {
          arrays.put(this, new Throwable());
        }
        combinedCapacity += size;
/*
	Reference r = new SoftReference(this, rq);
        r.enqueue();
*/
        byteArrays++;
        liveByteArrays++;
    }

  static {
    Thread t = new BigBufferMonitor();
    t.start();
/*
    t = new GcWatcher();
    t.start();
*/
  }

  private static ReferenceQueue rq = new ReferenceQueue();

  public void finalize() {
	  combinedCapacity -= buf.length;
	  combinedCount -= count;
          byteArrays--;
          byteArraysGCed++;
/*
	   System.out.println(" GCed " + byteArraysGCed + " - " + byteArrays + " BOS allocated");
	    StringWriter sw = new StringWriter();
	    PrintWriter pw = new PrintWriter(sw);
	    Throwable bigThrowable1 = (Throwable)arrays.get(this);
	    bigThrowable1.printStackTrace(pw);
	  System.out.println(this + "\n" + sw.toString());
*/
  }

  private static class BufferComparator implements Comparator {
    public int compare(Object o1, Object o2) {
      ByteArrayOutputStream bo1 = (ByteArrayOutputStream) o1;
      ByteArrayOutputStream bo2 = (ByteArrayOutputStream) o2;
     
      if (bo1 == null || bo2 == null) {
        return 1;
      } 
      if (bo1.buf.length < bo2.buf.length) {
	return 1;
      }
      else if (bo1.buf.length == bo2.buf.length) {
	return 0;
      }
      else return -1;
    }
  }

  private static class GcWatcher extends Thread {
    public void run() {
      for (; ; byteArraysGCed++) { 
	try {
	  Reference ref = rq.remove();
	  ByteArrayOutputStream bo = (ByteArrayOutputStream) ref.get();
	  combinedCapacity -= bo.buf.length;
	  combinedCount -= bo.count;
          byteArrays--;
          
	} catch (InterruptedException e) {
	  System.out.println("Error: " + e.getMessage());
	}
      }
    }
  }

  private static class BigBufferMonitor extends Thread {
    public void run() {
      while (true) {
	try {
	  Thread.sleep(10*1000);
	} catch (InterruptedException e) {};
	
	synchronized (arrays) {
	  List theArrays = new ArrayList(arrays.keySet());
	  Collections.sort(theArrays, new BufferComparator());
	  StringWriter sw = new StringWriter();
	  PrintWriter pw = new PrintWriter(sw);
	  pw.println("Count:" + combinedCount + " Capacity: " +
		     combinedCapacity + " Hm.size: " + arrays.size() 
                     + " GCed " + byteArraysGCed + " - " + byteArrays + " BOS allocated / " + liveByteArrays);
	  Iterator it = theArrays.iterator();
	  for (int i = 0 ; it.hasNext() && i < 2 ; i++) {
	    ByteArrayOutputStream bo = (ByteArrayOutputStream)it.next(); 
            if (bo == null) continue;
	    int bigCount1 = bo.count;
	    int bigBufSize1 = bo.buf.length;
	    Throwable bigThrowable1 = (Throwable)arrays.get(bo);
	    pw.println(" Top consumer [" + i + "] count: "
		       + bigCount1 + " size: " + bigBufSize1);
	    if (bigThrowable1 != null) {
	      bigThrowable1.printStackTrace(pw);
	    }
	  }
	  System.out.println(sw.toString());
	}
      }
    }
  }

    /**
     * Writes the specified byte to this byte array output stream. 
     *
     * @param   b   the byte to be written.
     */
    public synchronized void write(int b) {
	int newcount = count + 1;
	if (newcount > buf.length) {
	    byte newbuf[] = new byte[Math.max(buf.length << 1, newcount)];
	    System.arraycopy(buf, 0, newbuf, 0, count);
            combinedCapacity -= buf.length;
	    buf = newbuf;
            combinedCapacity += buf.length;
	}
	buf[count] = (byte)b;
	count = newcount;
        combinedCount++;
    }

    /**
     * Writes <code>len</code> bytes from the specified byte array 
     * starting at offset <code>off</code> to this byte array output stream.
     *
     * @param   b     the data.
     * @param   off   the start offset in the data.
     * @param   len   the number of bytes to write.
     */
    public synchronized void write(byte b[], int off, int len) {
	if ((off < 0) || (off > b.length) || (len < 0) ||
            ((off + len) > b.length) || ((off + len) < 0)) {
	    throw new IndexOutOfBoundsException();
	} else if (len == 0) {
	    return;
	}
        int newcount = count + len;
        if (newcount > buf.length) {
            byte newbuf[] = new byte[Math.max(buf.length << 1, newcount)];
            System.arraycopy(buf, 0, newbuf, 0, count);
            combinedCapacity -= buf.length;
            buf = newbuf;
            combinedCapacity += buf.length;
        }
        System.arraycopy(b, off, buf, count, len);
        count = newcount;
        combinedCount += len;
    }

    /**
     * Writes the complete contents of this byte array output stream to 
     * the specified output stream argument, as if by calling the output 
     * stream's write method using <code>out.write(buf, 0, count)</code>.
     *
     * @param      out   the output stream to which to write the data.
     * @exception  IOException  if an I/O error occurs.
     */
    public synchronized void writeTo(OutputStream out) throws IOException {
	out.write(buf, 0, count);
    }

    /**
     * Resets the <code>count</code> field of this byte array output 
     * stream to zero, so that all currently accumulated output in the 
     * ouput stream is discarded. The output stream can be used again, 
     * reusing the already allocated buffer space. 
     *
     * @see     java.io.ByteArrayInputStream#count
     */
    public synchronized void reset() {
        combinedCount -= count;
	count = 0;
    }

    /**
     * Creates a newly allocated byte array. Its size is the current 
     * size of this output stream and the valid contents of the buffer 
     * have been copied into it. 
     *
     * @return  the current contents of this output stream, as a byte array.
     * @see     java.io.ByteArrayOutputStream#size()
     */
    public synchronized byte toByteArray()[] {
	byte newbuf[] = new byte[count];
	System.arraycopy(buf, 0, newbuf, 0, count);
	return newbuf;
    }

    /**
     * Returns the current size of the buffer.
     *
     * @return  the value of the <code>count</code> field, which is the number
     *          of valid bytes in this output stream.
     * @see     java.io.ByteArrayOutputStream#count
     */
    public int size() {
	return count;
    }

    /**
     * Converts the buffer's contents into a string, translating bytes into
     * characters according to the platform's default character encoding.
     *
     * @return String translated from the buffer's contents.
     * @since   JDK1.1
     */
    public String toString() {
	return new String(buf, 0, count);
    }

    /**
     * Converts the buffer's contents into a string, translating bytes into
     * characters according to the specified character encoding.
     *
     * @param   enc  a character-encoding name.
     * @return String translated from the buffer's contents.
     * @throws UnsupportedEncodingException
     *         If the named encoding is not supported.
     * @since   JDK1.1
     */
    public String toString(String enc) throws UnsupportedEncodingException {
	return new String(buf, 0, count, enc);
    }

    /**
     * Creates a newly allocated string. Its size is the current size of 
     * the output stream and the valid contents of the buffer have been 
     * copied into it. Each character <i>c</i> in the resulting string is 
     * constructed from the corresponding element <i>b</i> in the byte 
     * array such that:
     * <blockquote><pre>
     *     c == (char)(((hibyte &amp; 0xff) &lt;&lt; 8) | (b &amp; 0xff))
     * </pre></blockquote>
     *
     * @deprecated This method does not properly convert bytes into characters.
     * As of JDK&nbsp;1.1, the preferred way to do this is via the
     * <code>toString(String enc)</code> method, which takes an encoding-name
     * argument, or the <code>toString()</code> method, which uses the
     * platform's default character encoding.
     *
     * @param      hibyte    the high byte of each resulting Unicode character.
     * @return     the current contents of the output stream, as a string.
     * @see        java.io.ByteArrayOutputStream#size()
     * @see        java.io.ByteArrayOutputStream#toString(String)
     * @see        java.io.ByteArrayOutputStream#toString()
     */
    public String toString(int hibyte) {
	return new String(buf, hibyte, 0, count);
    }

    /**
     * Closing a <tt>ByteArrayOutputStream</tt> has no effect. The methods in
     * this class can be called after the stream has been closed without
     * generating an <tt>IOException</tt>.
     * <p>
     *
     */
    public void close() throws IOException {
    }

}

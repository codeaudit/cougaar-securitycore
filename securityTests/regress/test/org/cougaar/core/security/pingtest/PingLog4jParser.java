/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 
package org.cougaar.core.security.pingtest;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FilenameFilter;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * @author srosset
 *
 */
public class PingLog4jParser {

  public void parseLog4jFiles(String dirname) throws ExperimentException
  {
    File dir = new File(dirname);
    if (!dir.isDirectory()) {
      throw new IllegalArgumentException("Must provide a directory name");
    }
    File files[] = dir.listFiles(new FilenameFilter() {
      public boolean accept(File parent, String file) {
        if (file.endsWith(".log")) {
          return true;
        }
        return false;
      }
    });
    if (files == null) {
      throw new ExperimentException("No log4j files found");
    }
    for (int i = 0 ; i < files.length ; i++) {
      try {
        parseLog4jFile(files[i]);
      } catch (IOException e) {
         throw new ExperimentException("Unable to read file: " + files[i]);
      }
    }
  }

  /**
   * @param file
   * @throws IOException
   */
  private void parseLog4jFile(File file) throws IOException {
    Pattern p = Pattern.compile("a*b");
    Matcher m = p.matcher("aaaaab");
    BufferedReader br = new BufferedReader(new FileReader(file));
    String line = null;
    while (( line = br.readLine()) != null) {
      
    }
  }
}

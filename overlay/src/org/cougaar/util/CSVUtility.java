/*
 * <copyright>
 *  Copyright 2003 BBNT Solutions, LLC
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 * 
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 * </copyright>
 * 
 * See original perl version of the parser (from japhy) at the end.
 */

package org.cougaar.util;

import java.util.regex.*;
import java.util.*;

public class CSVUtility {
  private CSVUtility() {}

  private static final Pattern p = Pattern.compile("\\G\\s*(?!$)(\\\"[^\\\"]*(?:\\\"\\\"[^\\\"]*)*\\\"|[^,\\\"]*),?");

  private static final String[] emptyStrings = new String[] {};

  /** Parse a single string in mocrosift-like CSV format **/
  public static String[] parse(String str) {
    ArrayList l = new ArrayList();
    Matcher m = p.matcher(str);
    while (m.find()) {
      String v = m.group(1);
      v.trim();
      if (v.length() > 1 && v.startsWith("\"") && v.endsWith("\"")) {
        v = v.substring(1,v.length()-1);
        v = v.replaceAll("\"\"", "\"");
      }
      l.add(v);
    }
    return (String[]) l.toArray(emptyStrings);
  }

  public static Collection parseToCollection(String str) {
    String[] elements = parse(str);
    int l = elements.length;
    ArrayList c = new ArrayList(l);
    for (int i=0; i<l; i++) {
      c.add(elements[i]);
    }
    return c;
  }
}  

/*
From the perl at http://japhy.perlmonk.org/

@fields = parseCSV(
  'this,that,"those,these, and mine","""I want those,"" he said"'
);

print map "($_)", @fields;


sub parseCSV {
  my $str = @_ ? shift : $_;
  my @ret;
  while ($str =~ /\G\s*(?!$)("[^"]*(?:""[^"]*)*"|[^,"]*),?/g) {
    push @ret, $1;
    $ret[-1] =~ s/\s+$//;
    if ($ret[-1] =~ s/^"//) { chop $ret[-1]; $ret[-1] =~ s/""/"/g }
  }
  return @ret;
}


__END__

$str =~ m{
  \G         # where the last match left off (defaults to ^)
  \s*        # any whitespace (we don't save this)
  (?!$)      # NOT followed by end-of-string
  (          # save this to $1 (this is ONE CSV)
    "        # a "
    [^"]*    # followed by 0 or more non-"
    (?:      # then...
      ""     # a "" (which is a CSV 'escape' for a ")
      [^"]*  # followed by 0 or more non-"
    )*       # 0 or more times
    "        # the ending "
    |        # *OR*
    [^,"]*   # 0 or more non-, and non-" characters
  )
  ,?         # with an optional ending comma
}gx;
*/

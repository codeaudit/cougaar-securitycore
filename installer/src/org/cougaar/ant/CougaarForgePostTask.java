/*
 * Created on Dec 3, 2004
 *
 * To change the template for this generated file go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
package org.cougaar.ant;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.tools.ant.BuildException;

/**
 * @author srosset
 *
 * To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
public class CougaarForgePostTask
  extends org.apache.tools.ant.Task
{
  private static final String LOGIN_SERVLET = "/account/login.php";
  private static final String UPLOAD_SERVLET = "/frs/admin/qrs.php?package_id=&group_id=";
  private static final String SEARCH_SERVLET = "/search/";
  private static final String PROJECTS_SERVLET = "/projects/";
  private static final String EDIT_RELEASE_SERVLET = "/frs/admin/editrelease.php";
  
  /** Storage for name/value pairs to send. */
  private Map props = new HashMap();
  
  // BEGIN ANT attributes
  /** URL to send the name/value pairs to. */
  private String url;
  private String username;
  private String password;
  private String unixprojectname;
  /** how long to wait for a response from the server */
  private long maxwait = 180000;   // units for maxwait is milliseconds
  // END ANT attributes
  
  private String sessionCookie;
  private String group_id;
  private boolean group_id_searched = false;
  private String package_id;
  private boolean package_id_searched = false;
  private String release_id;
  private boolean release_id_searched = false;
  private String file_id;
  private boolean file_id_searched = false;
  private boolean verbose;
  
  public void execute() throws BuildException {
    if (url == null) {
      throw new BuildException("SourceForge URL not specified");
    }
    if (username == null) {
      throw new BuildException("Username not specified");
    }
    if (password == null) {
      throw new BuildException("Password not specified");
    }
    try {
      login();
      getGroupId();
      getPackageId();
      getReleaseId();
      getFileId();
      deleteReleaseFile();
      
      Property p1a = new Property("package_id", getPackageId());
      addConfiguredProp(p1a);

      // "2004-12-03 22:10"
      SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd H:mm");
      String today = sdf.format(new Date());
      Property p1b = new Property("release_date", today);
      addConfiguredProp(p1b);

      String release_name = (String)props.get("release_name");
      Pattern p = Pattern.compile(".*-(\\w+)-(\\w+)");
      Matcher m = p.matcher(release_name);
      String securityBranch = null;
      String cougaarBranch = null;
      if (m.find()) {
        securityBranch = m.group(1);
        cougaarBranch = m.group(2);
      }
      Property p5 = new Property("release_notes",
          "This release contains a snapshot build of the security services.\n"
          + "Snapshots are not for production use and are not guaranteed to be working at any\n"
          + "particular point in time, and are only intended for those wishing to help with\n"
          + "development or alpha testing. This release contains security code from the\n"
          + "[" + securityBranch + "] branch built against the [" + cougaarBranch + "] Cougaar SE branch.");
      addConfiguredProp(p5);
      Property p7 = new Property("submit", "Release File");
      addConfiguredProp(p7);

      updateReleaseDate();
      if (getReleaseId() != null) {
        uploadFileToExistingRelease();
      }
      else {
        uploadNewFile();
      }
    }
    catch (Exception e) {
      throw new BuildException("Unable to POST data", e);
    }
  }
  
  public void addConfiguredProp(Property p) throws BuildException {
    String name = p.getName();
    if ( name == null ) {
       throw new BuildException( "name is null", getLocation() );
    }
    String value = p.getValue();
    if ( value == null ) {
       value = getProject().getProperty( name );
    }
    if ( value == null ) {
       throw new BuildException( "value is null", getLocation() );
    }
    props.put( name, value );
  }
  
  public void login() throws IOException {
    if (verbose) {
      System.out.println("login as " + getUsername());
    }
    URL u = new URL(getUrl() + LOGIN_SERVLET);
    HttpURLConnection huc = (HttpURLConnection)u.openConnection();
    huc.setInstanceFollowRedirects(false);
    //  Let the RTS know that we want to do output.
    huc.setDoOutput (true);
    String cookie = ClientHttpRequest.randomString();
    huc.setRequestProperty("Cookie", "session_ser=" + cookie);
    //  Specify the content type.
    huc.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

    //  Send POST output.
    DataOutputStream printout = new DataOutputStream (huc.getOutputStream ());
    String content =
      "return_to=" + URLEncoder.encode ("", "UTF-8") +
      "&form_loginname=" + URLEncoder.encode (getUsername(), "UTF-8") +
      "&form_pw=" + URLEncoder.encode (getPassword(), "UTF-8") +
      "&login=" + URLEncoder.encode("Login", "UTF-8");
    
    printout.writeBytes (content);
    printout.flush ();
    printout.close ();

    sessionCookie = huc.getHeaderField("Set-Cookie");
    //System.out.println("Set-Cookie: " + sessionCookie);
  }

  private void updateReleaseDate() throws IOException {
    String new_release_date = (String)props.get("release_date");
    if (new_release_date == null) {
      throw new RuntimeException("Release date has not been set");
    }
    String release_name = (String)props.get("release_name");
    if (release_name == null) {
      throw new RuntimeException("Release name has not been set");
    }
    if (verbose) {
      System.out.println("changeReleaseDate: " + release_name 
        + " - " + new_release_date);
    }
    if (getReleaseId() == null) {
      return;
    }
    String servlet = "/frs/admin/editrelease.php?group_id=" + getGroupId() +
      "&release_id=" + getReleaseId() + "&package_id=" + getPackageId();
    URL u = new URL(getUrl() + servlet);
    HttpURLConnection huc = (HttpURLConnection)u.openConnection();
    
    huc.setInstanceFollowRedirects(false);
    //  Let the RTS know that we want to do output.
    huc.setDoOutput (true);
    //  Specify the content type.
    huc.setRequestProperty("Cookie", sessionCookie);
    huc.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

    //  Send POST output.
    DataOutputStream printout = new DataOutputStream (huc.getOutputStream ());
    String content =
      "step1=" + URLEncoder.encode ("1", "UTF-8") +
      "&release_date=" + URLEncoder.encode (new_release_date, "UTF-8") +
      "&release_name=" + URLEncoder.encode (release_name, "UTF-8") +
      "&status_id=" + URLEncoder.encode ("1", "UTF-8") +
      "&uploaded_notes=" + URLEncoder.encode ("", "UTF-8") +
      "&release_notes=" + URLEncoder.encode ((String)props.get("release_notes"), "UTF-8") +
      "&release_changes=" + URLEncoder.encode ("", "UTF-8") +
      "&preformatted=" + URLEncoder.encode ("2", "UTF-8") +
      "&submit=" + URLEncoder.encode ("Submit/Refresh", "UTF-8");
    
    printout.writeBytes (content);
    printout.flush ();
    printout.close ();
  
    BufferedReader br = new BufferedReader(new InputStreamReader(huc.getInputStream ()));
    String str;
    //Data Saved
    boolean dataSaved = false;
    while (null != ((str = br.readLine())))
    {
      if (str.indexOf("Data Saved") > -1) {
        dataSaved = true;
      }
      //System.out.println (str);
    }
    br.close ();
    if (!dataSaved) {
      throw new RuntimeException("Unable to change release date");
    }
  }
  
  public void uploadFileToExistingRelease() throws IOException {
    File uploadFile = new File((String)props.get("userfile"));
    if (verbose) {
      System.out.println("uploadFileToExistingRelease: " + uploadFile);
    }
    if (!uploadFile.exists()) {
      throw new RuntimeException("File does not exist: " + uploadFile.getCanonicalPath());
    }
    if (getReleaseId() == null) {
      return;
    }
    String servlet = "/frs/admin/editrelease.php?group_id=" + getGroupId() +
      "&release_id=" + getReleaseId() + "&package_id=" + getPackageId();
    URL u = new URL(getUrl() + servlet);
    //  create a boundary string
    String boundary = MultiPartFormOutputStream.createBoundary();
    URLConnection urlConn = MultiPartFormOutputStream.createConnection(u);
    urlConn.setRequestProperty("Accept", "*/*");
    urlConn.setRequestProperty("Content-Type", 
      MultiPartFormOutputStream.getContentType(boundary));
     //     set some other request headers...
    urlConn.setRequestProperty("Connection", "Keep-Alive");
    urlConn.setRequestProperty("Cache-Control", "no-cache");
    urlConn.setRequestProperty("Cookie", sessionCookie);
    //     no need to connect cuz getOutputStream() does it
    MultiPartFormOutputStream out = 
      new MultiPartFormOutputStream(urlConn.getOutputStream(), boundary);
    out.writeField("step2", "1");
    out.writeFile("userfile", "text/plain", uploadFile);
    out.writeField("type_id", (String)props.get("type_id"));
    out.writeField("processor_id", (String)props.get("processor_id"));
    out.writeField("submit", "Add This File");
    out.close();

    BufferedReader br = new BufferedReader(new InputStreamReader(urlConn.getInputStream ()));
    String str;
    // File Released: You May Choose To Edit the Release Now
    boolean fileReleased = false;
    StringBuffer sb = new StringBuffer();
    while (null != ((str = br.readLine())))
    {
      sb.append(str);
      if (str.indexOf("File Released") > -1) {
        fileReleased = true;
      }
      //System.out.println (str);
    }
    br.close ();
    if (!fileReleased) {
      if (verbose) {
        System.out.println(sb.toString());
      }
      throw new RuntimeException("Unable to release file");
    }
    else {
      if (verbose) {
        System.out.println("File released - Release:" + props.get("release_name")
          + " Date: " + props.get("release_date")
          + " File: " + props.get("userfile"));
      }
    }
    
  }
  
  public void uploadNewFile() throws IOException {   
    if (verbose) {
      System.out.println("upload File " + props.get("userfile"));
    }
    File uploadFile = new File((String)props.get("userfile"));
    if (!uploadFile.exists()) {
      throw new RuntimeException("File does not exist: " + uploadFile.getCanonicalPath());
    }
    URL u = new URL(getUrl() + UPLOAD_SERVLET + getGroupId());
    //  create a boundary string
    String boundary = MultiPartFormOutputStream.createBoundary();
    URLConnection urlConn = MultiPartFormOutputStream.createConnection(u);
    urlConn.setRequestProperty("Accept", "*/*");
    urlConn.setRequestProperty("Content-Type", 
      MultiPartFormOutputStream.getContentType(boundary));
     //     set some other request headers...
    urlConn.setRequestProperty("Connection", "Keep-Alive");
    urlConn.setRequestProperty("Cache-Control", "no-cache");
    urlConn.setRequestProperty("Cookie", sessionCookie);
    //     no need to connect cuz getOutputStream() does it
    MultiPartFormOutputStream out = 
      new MultiPartFormOutputStream(urlConn.getOutputStream(), boundary);
    
    Iterator it = props.entrySet().iterator();
    StringBuffer sb = new StringBuffer();
    while (it.hasNext()) {
      Map.Entry me = (Map.Entry) it.next();
      String attr = (String) me.getKey();
      String value = (String) me.getValue();
      //System.out.print(attr + ": " + value + " - ");
      if (!attr.equals("userfile")) {
        out.writeField(attr, value);
      }
      else {
        out.writeFile(attr, "text/plain", uploadFile);
      }
    }
    //System.out.println();
    out.close();

    BufferedReader br = new BufferedReader(new InputStreamReader(urlConn.getInputStream ()));
    String str;
    // File Released: You May Choose To Edit the Release Now
    boolean fileReleased = false;
    while (null != ((str = br.readLine())))
    {
      if (str.indexOf("File Released: You May Choose To Edit the Release Now") > -1) {
        fileReleased = true;
      }
      //System.out.println (str);
    }
    br.close ();
    if (!fileReleased) {
      throw new RuntimeException("Unable to release file");
    }
    else {
      if (verbose) {
        System.out.println("File released - Release:" + props.get("release_name")
            + " Date: " + props.get("release_date")
            + " File: " + props.get("userfile"));
      }
    }
  }

  private String getGroupId() throws IOException {
    if (group_id_searched) {
      return group_id;
    }
    group_id_searched = true;
    if (verbose) {
      System.out.println("getGroupId of " + getUnixprojectname() + "project");
    }
    if (getUnixprojectname() == null) {
      throw new RuntimeException("Project name is not defined");
    }
    URL u = new URL(getUrl() + PROJECTS_SERVLET + getUnixprojectname());
    URLConnection huc = u.openConnection();
    huc.setRequestProperty("Cookie", sessionCookie);
    BufferedReader br = new BufferedReader(new InputStreamReader(huc.getInputStream ()));
    String str;
    // Look for the following pattern:
    // <a href="/news/?group_id=51">News
    Pattern p = Pattern.compile("<a href=\"/news/\\?group_id=(\\d+)\">News</a>");
    while (null != ((str = br.readLine())))
    {
      //System.out.println (str);
      Matcher m = p.matcher(str);
      if (m.find()) {
        group_id = m.group(1);
        if (verbose) {
          System.out.println("Group id=" + getGroupId());
        }
        break;
      }
    }
    br.close ();
    if (group_id == null) {
      throw new RuntimeException("Unable to find group ID");
    }
    return group_id;
  }
  
  private void search(String words) throws IOException {
    URL u = new URL(getUrl() + SEARCH_SERVLET);
    HttpURLConnection huc = (HttpURLConnection)u.openConnection();
    
    huc.setInstanceFollowRedirects(false);
    //  Let the RTS know that we want to do output.
    huc.setDoOutput (true);
    //  Specify the content type.
    huc.setRequestProperty("Cookie", sessionCookie);
    huc.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

    //  Send POST output.
    DataOutputStream printout = new DataOutputStream (huc.getOutputStream ());
    String content =
      "words=" + URLEncoder.encode (getUnixprojectname(), "UTF-8") +
      "&type_of_search=" + URLEncoder.encode ("soft", "UTF-8") +
      "&Search=" + URLEncoder.encode("Search", "UTF-8");
    
    printout.writeBytes (content);
    printout.flush ();
    printout.close ();
  
    BufferedReader br = new BufferedReader(new InputStreamReader(huc.getInputStream ()));
    String str;
    while (null != ((str = br.readLine())))
    {
      System.out.println (str);
    }
    br.close ();

  }
  
  private String getReleaseId() throws IOException {
    if (release_id_searched) {
      return release_id;
    }
    release_id_searched = true;
    String releaseName = (String)props.get("release_name");
    if (releaseName == null) {
      throw new RuntimeException("Release name not set");
    }
    if (verbose) {
      System.out.println("getReleaseId: " + releaseName);
    }
    String showReleaseServlet = "/frs/admin/showreleases.php?package_id=" + getPackageId() +
      "&group_id=" + getGroupId();
    URL u = new URL(getUrl() + showReleaseServlet);
    URLConnection huc = u.openConnection();
    huc.setRequestProperty("Cookie", sessionCookie);
    BufferedReader br = new BufferedReader(new InputStreamReader(huc.getInputStream ()));
    String str;
    // Look for the following pattern:
    // <a href="editrelease.php?group_id=51&amp;package_id=45&amp;release_id=94">securebootstrap-HEAD-HEAD [Edit]</a>
    String pattern = "release_id=(\\d+)\">" +
      releaseName + " \\[Edit\\]</a>";
    Pattern p = Pattern.compile(pattern);
    while (null != ((str = br.readLine())))
    {
      //System.out.println (str);
      Matcher m = p.matcher(str);
      if (m.find()) {
        release_id = m.group(1);
        if (verbose) {
          System.out.println("Release ID:" + release_id);
        }
        break;
      }
    }
    br.close ();
    if (release_id == null) {
      // It's ok. It may not have been created before.
      //throw new RuntimeException("Unable to find package ID");
    }
    return release_id;
  }
  
  private String getFileId() throws IOException {
    if (file_id_searched) {
      return file_id;
    }
    file_id_searched = true;
    String userfile = (String) props.get("userfile");
    if (userfile == null) {
      throw new RuntimeException("Userfile not specified");
    }
    File f = new File(userfile);
    userfile = f.getName();
    if (verbose) {
      System.out.println("getFileId: " + userfile);
    }
    if (getReleaseId() == null) {
      // There is no release. Go no further.
      return null;
    }
    String frsAdminServlet =
      "/frs/?group_id=" + getGroupId();
    URL u = new URL(getUrl() + frsAdminServlet);
    URLConnection huc = u.openConnection();
    huc.setRequestProperty("Cookie", sessionCookie);
    BufferedReader br = new BufferedReader(new InputStreamReader(huc.getInputStream ()));
    String str;
    // Look for the following patterns:
    // File pattern:
    //    <a href="/frs/clickthru.php?file_id=169&filename=test2.txt&group_id=51">test2.txt</a>
    // Release pattern
    // <a href="shownotes.php?release_id=95">secureboostrap-HEAD-HEAD</a>
    String filePattern = "<a href=\"/frs/clickthru\\.php\\?file_id=(\\d+)" +
      "&filename=\\Q" + userfile + "\\E&group_id=" + getGroupId();
    Pattern fPattern = Pattern.compile(filePattern);

    String releasePattern = "<a href=\"shownotes\\.php\\?release_id=(\\d+)";
    Pattern rPattern = Pattern.compile(releasePattern);
    boolean releaseGood = false;
    while (null != ((str = br.readLine())))
    {
      //System.out.println (str);
      Matcher m1 = rPattern.matcher(str);
      if (m1.find()) {
        // Is it the same release ID?
        if (getReleaseId().equals(m1.group(1))) {
          if (verbose) {
            System.out.println("Release is the one we are looking for: " + m1.group(1));
          }
          releaseGood = true;
        }
        else {
          if (verbose) {
            System.out.println("Release is not the one we are looking for: " + m1.group(1));
          }
          releaseGood = false;
        }
      }
      if (releaseGood) {
        Matcher m = fPattern.matcher(str);
        if (m.find()) {
          file_id = m.group(1);
          if (verbose) {
            System.out.println("File ID:" + file_id);
          }
          break;
        }
      }
    }
    br.close ();
    if (file_id == null) {
      // That's ok. The file may not exist yet
      //throw new RuntimeException("Unable to find package ID");
    }
    return file_id;
  }
  private String getPackageId() throws IOException {
    if (package_id_searched) {
      return package_id;
    }
    package_id_searched = true;
    if (verbose) {
      System.out.println("getPackageId");
    }
    URL u = new URL(getUrl() + UPLOAD_SERVLET + getGroupId());
    URLConnection huc = u.openConnection();
    huc.setRequestProperty("Cookie", sessionCookie);
    BufferedReader br = new BufferedReader(new InputStreamReader(huc.getInputStream ()));
    String str;
    // Look for the following pattern:
    // <select name="package_id"><option value="45">
    Pattern p = Pattern.compile("<select name=\"package_id\"><option value=\"(\\d+)\">");
    while (null != ((str = br.readLine())))
    {
      //System.out.println (str);
      Matcher m = p.matcher(str);
      if (m.find()) {
        package_id = m.group(1);
        if (verbose) {
          System.out.println("Package ID:" + package_id);
        }
        break;
      }
    }
    br.close ();
    if (package_id == null) {
      throw new RuntimeException("Unable to find package ID");
    }
    return package_id;
  }
  
  // http://cougaar.org/frs/admin/editrelease.php?group_id=51&package_id=45&release_id=94
  
  private void deleteReleaseFile() throws IOException {
    // The file to be deleted
    String userfile = (String) props.get("userfile");
    if (userfile == null) {
      throw new RuntimeException("Userfile not specified");
    }
    File f = new File(userfile);
    userfile = f.getName();
    if (verbose) {
      System.out.println("deleteReleaseFile: " + userfile);
    }
    if (getReleaseId() == null || getFileId() == null) {
      // The file does not exist yet. No need to delete it.
      return;
    }

    URL u = new URL(getUrl() + EDIT_RELEASE_SERVLET);
    HttpURLConnection huc = (HttpURLConnection)u.openConnection();
    
    huc.setInstanceFollowRedirects(false);
    //  Let the RTS know that we want to do output.
    huc.setDoOutput (true);
    //  Specify the content type.
    huc.setRequestProperty("Cookie", sessionCookie);
    huc.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

    //  Send POST output.
    DataOutputStream printout = new DataOutputStream (huc.getOutputStream ());
    String content =
      "group_id=" + URLEncoder.encode (getGroupId(), "UTF-8") +
      "&release_id=" + URLEncoder.encode (getReleaseId(), "UTF-8") +
      "&package_id=" + URLEncoder.encode(getPackageId(), "UTF-8") +
      "&file_id=" + URLEncoder.encode(getFileId(), "UTF-8") +
      "&step3=" + URLEncoder.encode("Delete File", "UTF-8") +
      "&submit=" + URLEncoder.encode("Delete File", "UTF-8") +
      "&im_sure=" + URLEncoder.encode("2", "UTF-8");
    
    printout.writeBytes (content);
    printout.flush ();
    printout.close ();
  
    BufferedReader br = new BufferedReader(new InputStreamReader(huc.getInputStream ()));
    String str;
    // Search Pattern:
    // File Deleted
    boolean isDeleted = false;
    while (null != ((str = br.readLine())))
    {
      if (str.indexOf("File Deleted") > -1) {
        isDeleted = true;
      }
    }
    br.close ();
    if (!isDeleted) {
      // Something was wrong. We were unable to delete the file.
      throw new RuntimeException("Unable to delete release file");
    }
  }
  
  /**
   * @return Returns the password.
   */
  public String getPassword() {
    return password;
  }
  /**
   * @param password The password to set.
   */
  public void setPassword(String password) {
    this.password = password;
  }

  /**
   * @return Returns the username.
   */
  public String getUsername() {
    return username;
  }
  /**
   * @param username The username to set.
   */
  public void setUsername(String username) {
    this.username = username;
  }
  /**
   * @return Returns the maxwait.
   */
  public long getMaxwait() {
    return maxwait;
  }
  /**
   * @param maxwait The maxwait to set.
   */
  public void setMaxwait(long maxwait) {
    this.maxwait = maxwait * 1000;
  }
  /**
   * @return Returns the url.
   */
  public String getUrl() {
    return url;
  }
  /**
   * @param loginUrl The url to set.
   */
  public void setUrl(String url) {
    this.url = url;
  }
  
  /**
   * @return Returns the unixprojectname.
   */
  public String getUnixprojectname() {
    return unixprojectname;
  }
  /**
   * @param projectname The unixprojectname to set.
   */
  public void setUnixprojectname(String unixprojectname) {
    this.unixprojectname = unixprojectname;
  }
  /**
   * @return Returns the verbose.
   */
  public boolean getVerbose() {
    return verbose;
  }
  /**
   * @param verbose The verbose to set.
   */
  public void setVerbose(boolean verbose) {
    this.verbose = verbose;
  }
  /*
  <post to="${cougaarforge.post.url}"
    verbose="true">
<prop name="userfile"     value="${overlay.zip.name}"/>
<prop name="release_name" value="${project.name}-${anthill.branch.name}-${cougaar.branch.name}"/>
<prop name="type_id"      value="3000"/>
<prop name="processor_id" value="8000"/>
</post>
*/

  public static void main(String args[]) {
    CougaarForgePostTask hp = new CougaarForgePostTask();
    try {
      String cwd = System.getProperty("user.dir");
      String fileName = "test.foo.bar";
      File f = new File(cwd, fileName);
      if (!f.exists()) {
        throw new RuntimeException("Unable to find " + fileName + " under " + cwd);
      }
      System.out.println("File: " + f.getAbsolutePath());
      String releaseName = "securebootstrap-SNAPSHOT-HEAD-HEAD";
      
      hp.setPassword("");
      hp.setUrl("http://cougaar.org");
      hp.setUsername("");
      hp.setVerbose(true);
      hp.setUnixprojectname("securebootstrap");
      Property p1 = new Property("userfile", fileName);
      hp.addConfiguredProp(p1);
      Property p2 = new Property("release_name", releaseName);
      hp.addConfiguredProp(p2); 
      Property p3 = new Property("type_id", "3000");
      hp.addConfiguredProp(p3);
      Property p4 = new Property("processor_id", "8000");
      hp.addConfiguredProp(p4);
      Property p6 = new Property("release_changes", "");
      hp.addConfiguredProp(p6);
      hp.execute();
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

}

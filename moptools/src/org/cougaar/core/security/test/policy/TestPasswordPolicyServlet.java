package org.cougaar.core.security.test.policy;

import org.cougaar.core.servlet.BaseServletComponent;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.Servlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.util.List;

public class TestPasswordPolicyServlet extends BaseServletComponent{
 private String path;
  public void load() {
    super.load();
  }

  protected String getPath() {
    return path;
  }
  public void setParameter(Object o) {
    List l=(List)o;
    path=(String)l.get(0);
  }
  
  protected Servlet createServlet() {
    return new PasswordPolicyServlet();
  }

  public void unload() {
    super.unload();
    // FIXME release the rest!
  }
  
  private class PasswordPolicyServlet extends HttpServlet {
    
    public void doGet(HttpServletRequest request,
                      HttpServletResponse response)
      throws IOException {
         response.setContentType("text/html");
         PrintWriter out = response.getWriter();
         out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
         out.println("<html>");
         out.println("<head>");
         out.println("<title>Servlet to test policy  </title>");
         out.println("</head>");
         out.println("<body>");
         out.println("<H2>Servlet to test policy </H2>");
         out.println("</body></html>");
         out.flush();
         out.close();
    }
    
    public void doPost(HttpServletRequest request,
                       HttpServletResponse response)
      throws IOException {
      doGet(request,response);
    }
      
  } 
}

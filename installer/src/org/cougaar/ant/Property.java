/*
 * Created on Dec 3, 2004
 *
 * To change the template for this generated file go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
package org.cougaar.ant;


public class Property {
  private String name;
  private String value;
  
  public Property() {
  }
  
  public Property(String name, String value) {
    this.name = name;
    this.value = value;
  }
  
  /**
   * @return Returns the name.
   */
  public String getName() {
    return name;
  }
  /**
   * @param name The name to set.
   */
  public void setName(String name) {
    this.name = name;
  }
  /**
   * @return Returns the value.
   */
  public String getValue() {
    return value;
  }
  /**
   * @param value The value to set.
   */
  public void setValue(String value) {
    this.value = value;
  }
}
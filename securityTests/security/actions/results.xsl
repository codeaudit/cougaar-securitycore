<?xml version="1.0" encoding="ISO-8859-1"?>

<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:template match="/">
  <html>
  <body>
    <h2>Security Experiment Results</h2>
    <xsl:apply-templates/> 
  </body>
  </html>
</xsl:template>

<xsl:template match="securityEvents/plannedSecurityExperiments">
    <h3>Security Planned Test Cases</h3>
    <table border="1">
    <tr bgcolor="#9acd32">
      <th align="left">Test Case Name</th>
    </tr>
    <xsl:for-each select="plannedTest">
      <tr>
        <td><xsl:value-of select="."/></td>
      </tr>
    </xsl:for-each>
    </table>
</xsl:template>

<xsl:template match="securityEvents">
    <h3>Security Test Case Results</h3>
    <table border="1">
    <tr bgcolor="#9acd32">
      <th align="left">Time</th>
      <th align="left">TestId</th>
      <th align="left">Description</th>
    </tr>
    <xsl:for-each select="event">
    <tr>
      <xsl:choose>
      <xsl:when test="success='true'">
        <!-- #33ff33 : Green --> 
        <td bgcolor="#33ff33"><xsl:value-of select="date"/></td>
        <td bgcolor="#33ff33"><xsl:value-of select="testId"/></td>
        <td bgcolor="#33ff33"><xsl:value-of select="description"/></td>
      </xsl:when>
      <xsl:otherwise>
        <!-- #ff6633 : Red --> 
        <td bgcolor="#ff6633"><xsl:value-of select="date"/></td>
        <td bgcolor="#ff6633"><xsl:value-of select="testId"/></td>
        <td bgcolor="#ff6633"><xsl:value-of select="description"/></td>
      </xsl:otherwise>
      </xsl:choose>
    </tr>
    </xsl:for-each>
    </table>
</xsl:template>

</xsl:stylesheet>

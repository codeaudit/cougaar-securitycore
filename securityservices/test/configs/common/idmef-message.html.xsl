<?xml version="1.0" ?>

<!--***************************************************************************

$Id: idmef-message.html.xsl,v 1.1 2002-04-24 18:42:31 srosset Exp $

idmef-message.html.xsl
Version 0.50

A basic XSL stylesheet to convert IDMEF alerts into HTML.

Copyright (C) 2001 The Aerospace Corporation

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License at http://www.gnu.org/copyleft/gpl.txt
for more details.

Created by Ben Feinstein, bfeinste@hmc.edu, Oct 08 2000 for the
Aerospace Corp. Harvey Mudd College Computer Science Clinic 2000-2001


KNOWN BUGS:

*  Will not work with XML files that contain the IDMEF DOCTYPE declaration.

*  Does not enforce req. that the IDMEF-Message version equals "0.1".

*  Does not enforce req. that ident attribute be present for Service elements.


TO DO:

*  Update stylesheet to reflect newest IDMEF changes per the IDWG meeting in
   Dec. 2000.

*  Add support for the Heartbeat element of an IDMEF-Message.

*  Fix bug where XSLT processor will not transform files that contain an
   IDMEF DOCTYPE declaration.

*  Move away from having the stylesheet try and enforce IDMEF requirements.
   Instead the stylesheet should be more forgiving with what is accepted,
   while indicating the ways in which the message violates the IDMEF draft.


****************************************************************************-->


<!-- 

	Top-level tag <xsl:stylesheet>

	The XSL namespace has the URI http://www.w3.org/1999/XSL/Transform.

	NOTE: The 1999 in the URI indicated the year in which the URI was allocated by the W3C.
	It does not indicate the version of XSL being used.

-->


<xsl:stylesheet
	xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
	version="1.0">

	<!--
		Root template is called first.  Here we output HTML headers
		and begin table element.
	-->

	<xsl:template match="/">
		<html>
		<title>IDMEF events</title>
		<body bgcolor="#ffffff">
		<table border="1" cellpadding="10">
		<tr>
			<td><b><i>Alert ID</i></b></td>
			<td><b><i>Impact</i></b></td>
			<td><b><i>Date/Time</i></b></td>
			<td><b><i>Analyzer</i></b></td>
			<td><b><i>Classification</i></b></td>
			<td><b><i>Source</i></b></td>
			<td><b><i>Target</i></b></td>
			<td><b><i>Specific Alerts</i></b></td>
		</tr>

		<xsl:for-each select="IDMEF-Message/Alert[@alertid and @impact]">

		<!-- sort Alerts by date and time -->
		<xsl:sort order="ascending" select="Time/date" />
		<xsl:sort order="ascending" select="Time/time" />

		<tr>
			<td><xsl:value-of select="@alertid" /></td>
			<td><xsl:value-of select="@impact" /></td>
			<td><xsl:apply-templates select="Time" /></td>
			<td><xsl:apply-templates select="Analyzer" /></td>
			<td><xsl:apply-templates select="Classification" /></td>
			<td><xsl:apply-templates select="Source" /></td>
			<td><xsl:apply-templates select="Target" /></td>
			<td>
			<xsl:apply-templates select="ToolAlert" />
			<xsl:apply-templates select="OverflowAlert" />
			<xsl:apply-templates select="CorrelationAlert" />
			</td>

		</tr>

		</xsl:for-each>

		</table>
		</body>
		</html>

	</xsl:template>

	
	<xsl:template match="Time[ntpstamp and date and time]">
		<p>
		<xsl:text>Sent: </xsl:text>
		<xsl:value-of select="date" />
		<xsl:text> </xsl:text>
		<xsl:value-of select="time" />
		<xsl:value-of select="@offset" />
		<!-- <xsl:value-of select="ntpstamp" /> -->
		</p>

		<xsl:apply-templates select="DetectTime" />
		<xsl:apply-templates select="AnalyzerTime" />

	</xsl:template>


	<xsl:template match="DetectTime">
		<p>
		<xsl:text>Detected: </xsl:text>
		<xsl:value-of select="date" />
		<xsl:text> </xsl:text>
		<xsl:value-of select="time" />
		<xsl:value-of select="@offset" />
		<!-- <xsl:value-of select="ntpstamp" /> -->
		</p>
	</xsl:template>


	<xsl:template match="AnalyzerTime">
		<p>
		<xsl:text>Analyzer Date/Time: </xsl:text>
		<xsl:value-of select="date" />
		<xsl:text> </xsl:text>
		<xsl:value-of select="time" />
		<xsl:value-of select="@offset" />
		<!-- <xsl:value-of select="ntpstamp" /> -->
		</p>
	</xsl:template>


	<xsl:template match="Analyzer[@ident]">
		<p>
		<xsl:text>ID: </xsl:text>
		<xsl:value-of select="@ident" />
		</p>

		<xsl:if test="Node">
		<p>
			<!-- <xsl:text>Node:</xsl:text> -->
			<xsl:apply-templates select="Node" />
		</p>
		</xsl:if>

		<xsl:if test="Process">
		<p>
			<!-- <xsl:text>Process:</xsl:text> -->
			<xsl:apply-templates select="Process" />
		</p>
		</xsl:if>

	</xsl:template>


	<xsl:template match="Node">
		<xsl:text>Node:</xsl:text>

		<ul>

		<xsl:if test="@ident">
			<li>
			<xsl:text>ID: </xsl:text>
			<xsl:value-of select="@ident" />
			</li>
		</xsl:if>

                <xsl:if test="@category">
			<li>
			<xsl:text>Category: </xsl:text>
			<xsl:value-of select="@category" />
			</li>
		</xsl:if>

                <xsl:if test="name">
		        <li>
			<xsl:text>Name: </xsl:text>
			<xsl:value-of select="name" />
			</li>
		</xsl:if>

                <xsl:if test="location">
                        <li>
			<xsl:text>Location: </xsl:text>
			<xsl:value-of select="location" />
			</li>
                </xsl:if>

		<xsl:for-each select="Address">
			<li>
			<xsl:apply-templates select="." />
			</li>
		</xsl:for-each>

		</ul>

	</xsl:template>


	<xsl:template match="Address[@category and address]">
		<xsl:text>Address:</xsl:text>

		<ul>

		<xsl:if test="@ident">
			<li>
			<xsl:text>ID: </xsl:text>
			<xsl:value-of select="@ident" />
			</li>
		</xsl:if>

		<li>
		<xsl:text>Category: </xsl:text>
		<xsl:value-of select="@category" />
		</li>

		<li>
		<xsl:text>Address: </xsl:text>
		<xsl:value-of select="address" />
		</li>

		<xsl:if test="netmask">
			<li>
			<xsl:text>Netmask: </xsl:text>
			<xsl:value-of select="netmask" />
			</li>
		</xsl:if>

		</ul>
	</xsl:template>


        <xsl:template match="Process[name]">
		<xsl:text>Process:</xsl:text>

		<ul>

                <xsl:if test="@ident">
			<li>
                        <xsl:text>ID: </xsl:text>
                        <xsl:value-of select="@ident" />
                        </li>
                </xsl:if>

		<li>
			<xsl:text>Name: </xsl:text>
			<xsl:value-of select="name" />
		</li>

                <xsl:if test="pid">
                        <li>
			<xsl:text>PID: </xsl:text>
			<xsl:value-of select="pid" />
			</li>
                </xsl:if>

                <xsl:if test="path">
                        <li>
			<xsl:text>Path: </xsl:text>
			<xsl:value-of select="path" />
			</li>
                </xsl:if>

                <xsl:if test="Arguments">
                        <li>
			<!-- <xsl:text>Arguments:</xsl:text> -->
			<xsl:apply-templates select="Arguments" />
			</li>
                </xsl:if>

                <xsl:if test="Environment">
                        <li>
			<!-- <xsl:text>Environment:</xsl:text> -->
			<xsl:apply-templates select="Environment" />
			</li>
                </xsl:if>

		</ul>

        </xsl:template>


	<xsl:template match="Arguments">
		<xsl:text>Arguments:</xsl:text>

		<ul>

		<xsl:for-each select="arg">
			<li><xsl:value-of select="." /></li>
		</xsl:for-each>

		</ul>
	</xsl:template>


        <xsl:template match="Environment">
		<xsl:text>Environment:</xsl:text>

                <ul>

                <xsl:for-each select="env">
                        <li><xsl:value-of select="." /></li>
                </xsl:for-each>

                </ul>
        </xsl:template>


	<xsl:template match="Classification[name and url]">
		<p>

		<a href="{url}"><xsl:value-of select="name" /></a>

                <xsl:if test="@origin">
                        <xsl:text>  (Origin: </xsl:text>
                        <xsl:value-of select="@origin" />
                        <xsl:text>)</xsl:text>
                </xsl:if>

		</p>
	</xsl:template>


	<xsl:template match="Source[@spoofed]">
		<p>
		<xsl:text>Source:</xsl:text>
		<ul>

		<xsl:if test="@sourceid">
		        <li>
			<xsl:text>ID: </xsl:text>
			<xsl:value-of select="@sourceid" />
			</li>
                </xsl:if>

		<li>
		<xsl:text>Spoofed: </xsl:text>
		<xsl:value-of select="@spoofed" />
		</li>

		<xsl:if test="Node">
			<li>
			<xsl:apply-templates select="Node" />
			</li>
		</xsl:if>

                <xsl:if test="User">
			<li>
                        <xsl:apply-templates select="User" />
			</li>
                </xsl:if>

		<xsl:if test="Process">
			<li>
			<xsl:apply-templates select="Process" />
			</li>
		</xsl:if>

		</ul></p>

	</xsl:template>


        <xsl:template match="User[@category]">
		<xsl:text>User:</xsl:text>
		<ul>

                <xsl:if test="@ident">
                        <li>
			<xsl:text>ID: </xsl:text>
			<xsl:value-of select="@ident" />
			</li>
                </xsl:if>

                <li>
		<xsl:text>Category: </xsl:text>
		<xsl:value-of select="@category" />
		</li>

                <xsl:if test="name">
                        <li>
			<xsl:text>Name: </xsl:text>
			<xsl:value-of select="name" />
			</li>
                </xsl:if>

                <xsl:if test="uid">
                        <li>
			<xsl:text>UID: </xsl:text>
			<xsl:value-of select="uid" />
			</li>
                </xsl:if>

                <xsl:if test="group">
                        <li>
			<xsl:text>Group: </xsl:text>
			<xsl:value-of select="group" />
			</li>
                </xsl:if>

                <xsl:if test="gid">
                        <li>
			<xsl:text>GID: </xsl:text>
			<xsl:value-of select="gid" />
			</li>
                </xsl:if>

                <xsl:if test="serial">
                        <li>
			<xsl:text>Serial: </xsl:text>
			<xsl:value-of select="serial" />
			</li>
                </xsl:if>

                <xsl:for-each select="Address">
                        <li>
                        <xsl:apply-templates select="." />
                        </li>
                </xsl:for-each>

		</ul>
        </xsl:template>


	<xsl:template match="Target[@decoy]">
		<p>
		<xsl:text>Target:</xsl:text>
		<ul>

                <xsl:if test="@targetid">
                        <li>
                        <xsl:text>ID: </xsl:text>
                        <xsl:value-of select="@targetid" />
                        </li>
                </xsl:if>

                <li>
                <xsl:text>Decoy: </xsl:text>
                <xsl:value-of select="@decoy" />
                </li>

                <xsl:if test="Node">
                        <li>
                        <xsl:apply-templates select="Node" />
                        </li>
                </xsl:if>

                <xsl:if test="User">
                        <xsl:apply-templates select="User" />
                </xsl:if>

                <xsl:if test="Process">
                        <li>
                        <xsl:apply-templates select="Process" />
                        </li>
                </xsl:if>

                <xsl:if test="Service">
			<li>
			<xsl:apply-templates select="Service" />
			</li>
                </xsl:if>

		</ul></p>

	</xsl:template>

	
	<!-- According to the draft, service needs @ident, but the examples
	don't seem to have it.  I'll ignore the req. and check in the
	template. -->
	<xsl:template match="Service">
	<!-- <xsl:template match="Service[@ident]"> -->
		<xsl:text>Service:</xsl:text>

		<ul>

		<xsl:if test="@ident">
		        <li>
			<xsl:text>ID: </xsl:text>
			<xsl:value-of select="@ident" />
			</li>
		</xsl:if>

		<xsl:if test="name">
			<li>
			<xsl:text>Name: </xsl:text>
			<xsl:value-of select="name" />
			</li>
		</xsl:if>

		<xsl:if test="dport">
			<li>
			<xsl:text>Dest. port: </xsl:text>
			<xsl:value-of select="dport" />
			</li>
		</xsl:if>

                <xsl:if test="sport">
                        <li>
			<xsl:text>Source port: </xsl:text>
			<xsl:value-of select="sport" />
			</li>
		</xsl:if>

                <xsl:if test="protocol">
                        <li>
			<xsl:text>Protocol: </xsl:text>
			<xsl:value-of select="protocol" />
			</li>
		</xsl:if>

                <xsl:if test="portlist">
                        <li>
			<xsl:text>Port list: </xsl:text>
			<xsl:value-of select="portlist" />
			</li>
		</xsl:if>

                <xsl:if test="SNMPService">
			<li>
			<xsl:apply-templates select="SNMPService" />
			</li>
		</xsl:if>

                <xsl:if test="WebService">
                        <li>
			<xsl:apply-templates select="WebService" />
			</li>
		</xsl:if>

		</ul>

        </xsl:template>


        <xsl:template match="SNMPService">
		<xsl:text>SNMP Service:</xsl:text>
		<ul>

		<xsl:if test="@ident">
			<li>
			<xsl:text>ID: </xsl:text>
			<xsl:value-of select="@ident" />
			</li>
		</xsl:if>

                <xsl:if test="oid">
                        <li>
			<xsl:text>Object ID: </xsl:text>
			<xsl:value-of select="oid" />
			</li>
		</xsl:if>

                <xsl:if test="community">
                        <li>
			<xsl:text>Community: </xsl:text>
			<xsl:value-of select="community" />
			</li>
		</xsl:if>

                <xsl:if test="command">
                        <li>
			<xsl:text>Command: </xsl:text>
			<xsl:value-of select="command" />
			</li>
		</xsl:if>

		</ul>
        </xsl:template>


        <xsl:template match="WebService[url]">
		<xsl:text>Web Service:</xsl:text>
		<ul>

                <xsl:if test="@ident">
                        <li>
			<xsl:text>ID: </xsl:text>
			<xsl:value-of select="@ident" />
			</li>
		</xsl:if>

		<li>
		<xsl:text>URL: </xsl:text>
		<xsl:value-of select="url" />
		</li>

                <xsl:if test="cgi">
                        <li>
			<xsl:text>CGI: </xsl:text>
			<xsl:value-of select="cgi" />
			</li>
		</xsl:if>

                <xsl:if test="method">
                        <li>
			<xsl:text>Method: </xsl:text>
			<xsl:value-of select="method" />
			</li>
		</xsl:if>

                <xsl:if test="Arguments">
                        <li>
			<xsl:apply-templates select="Arguments" />
			</li>
		</xsl:if>

		</ul>
        </xsl:template>


	<xsl:template match="ToolAlert[name]">
		<p>
		<xsl:text>Tool Alert:</xsl:text>
		<ul>

		<li>
		<xsl:text>Name: </xsl:text>
		<xsl:value-of select="name" />
		</li>

		<xsl:if test="command">
			<li>
			<xsl:text>Command: </xsl:text>
			<xsl:value-of select="command" />
			</li>
		</xsl:if>

                <xsl:if test="alertid">
                        <li>

			<xsl:text>Alert ID:</xsl:text>

			<ul>
			<xsl:for-each select="alertid">
				<li>
				<xsl:value-of select="." />
				</li>
			</xsl:for-each>

			</ul>

                        </li>
                </xsl:if>

		</ul></p>
	</xsl:template>


	<xsl:template match="OverflowAlert[program and size]">
		<p>
		<xsl:text>Overflow Alert:</xsl:text>
		<ul>

		<li>
		<xsl:text>Program: </xsl:text>
		<xsl:value-of select="program" />
		</li>

                <li>
                <xsl:text>Buffer size (bytes): </xsl:text>
                <xsl:value-of select="size" />
                </li>

		<xsl:if test="buffer">
			<li>
			<xsl:text>Buffer:</xsl:text>
			<ul>
			<xsl:for-each select="buffer">
				<li>
				<xsl:value-of select="." />
				</li>
			</xsl:for-each>
			</ul></li>
		</xsl:if>

		</ul></p>
	</xsl:template>


	<xsl:template match="CorrelationAlert[alertid]">
		<p>
		<xsl:text>Correlation Alert:</xsl:text>
		<ul>

		<xsl:text>Alert ID:</xsl:text>

		<ul>

		<xsl:for-each select="alertid">
			<li>
			<xsl:value-of select="." />
			</li>
		</xsl:for-each>

		</ul>

		</ul></p>
	</xsl:template>


	<!--
	<xsl:template match="AdditionalData">
	</xsl:template>
	-->


</xsl:stylesheet>





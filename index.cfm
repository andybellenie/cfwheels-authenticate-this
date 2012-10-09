<h1>Authenticate This 1.0</h1>
<h3>A plugin for <a href="http://cfwheels.org" target="_blank">Coldfusion on Wheels</a> by <a href="http://cfwheels.org/user/profile/24" target="_blank">Andy Bellenie</a></h3>
<p>Adds salt and hash authentication and password reset to any model.</p>
<h2>Setup</h2>
<p>Add authenticateThis() to the init block of any model. You must provide a number of hash iterations as an argument. This number should be big (1000+) to make dictionary attacks difficult.</p>
<pre>&lt;cfcomponent extends=&quot;Wheels&quot; output=&quot;false&quot;&gt;
	&lt;cffunction name=&quot;init&quot;&gt;
		&lt;cfset authenticateThis(hashIterations=[big number])&gt;
	&lt;/cffunction&gt;<br />&lt;/cfcomponent&gt;</pre>
<h2>Usage</h2>
<p>By default the plugin uses the SHA-512 hashing algorithm. This can be changed to any algorithm that Coldfusion accepts.</p>
<h2>Support</h2>
<p>I try to keep my plugins free from bugs and up to date with Wheels releases, but life often gets in the way. If you encounter a problem please log an issue using the tracker on github, where you can also browse my other plugins.<br />
<a href="https://github.com/andybellenie" target="_blank">https://github.com/andybellenie</a></p>
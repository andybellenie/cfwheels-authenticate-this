<cfcomponent displayname="Authenticate This" output="false" author="Andy Bellenie" support="andy@dontpanicsolutions.co.uk">

	
	<!--- plugin config --->
	
	<cffunction name="init" output="false">
		<cfset this.version = "1.1,1.1.1,1.1.2,1.1.3,1.1.4,1.1.5,1.1.6,1.1.7,1.1.8">
		<cfreturn this>
	</cffunction>

	
	
	<!--- setup --->
	
	<cffunction name="authenticateThis">
		<cfargument name="loginProperty" type="string" default="username" hint="I am the name of the persistent property for login, commonly a username or email address.">
		<cfargument name="passwordHashProperty" type="string" default="passwordHash" hint="I am the name of the persistent property for the hashed password.">
		<cfargument name="passwordSaltProperty" type="string" default="passwordSalt" hint="I am the name of the persistent property for the password salt.">
		<cfargument name="passwordProperty" type="string" default="password" hint="I am the name of the virtual property for the password.">
		<cfargument name="failedLoginsProperty" type="string" default="failedLogins" hint="I am the name of the property for the number of failed logins.">
		<cfargument name="lockedUntilProperty" type="string" default="lockedUntil" hint="I am the name of the property for the locked until date.">
		<cfargument name="passwordFormatRegEx" type="string" default="^.*(?=.{8,})(?=.*\d)(?=.*[a-z]).*$" hint="I am a regular expression that enforces the format of the password.">
		<cfargument name="passwordFormatMessage" type="string" default="Your password must be at least 8 characters long and contain a mixture of numbers and letters" hint="I am the error message returned if the password is invalid.">
		<cfargument name="hashIterations" type="numeric" required="true" hint="I am the number of iterations of the salt/hash process. I should be big (1000+).">
		<cfset validatesFormatOf(property="password", regEx=arguments.passwordFormatRegEx, message=arguments.passwordFormatMessage, allowBlank=true)>
		<cfset validatesConfirmationOf(property="password", allowBlank=true)>
		<cfset beforeValidation(methods="$authenticate_hashPassword")>
	</cffunction>
	
	
	
	<!--- callbacks --->
	
	<cffunction name="$authenticate_hashPassword" returntype="void" output="false">
		<cfif this.hasChanged("password")>
			<cfset this.passwordSalt = GenerateSecretKey("AES")>
			<cfset this.passwordHash = this.saltAndHash(this.password, this.passwordSalt)>
		</cfif>
	</cffunction>
	
	

	<!--- api --->

	<cffunction name="checkPassword" returntype="boolean" output="false">
		<cfargument name="password" type="string" required="true">
		<cfif (not IsDate(this.lockedUntil) or DateCompare(this.lockedUntil, utcNow()) lt 1) and CompareNoCase(this.passwordHash, this.saltAndHash(arguments.password, this.passwordSalt)) eq 0> <!--- password ok --->
			<cfset this.update(failedLoginAttempts=0, lockedUntil="")>
			<cfreturn true>
		<cfelseif this.failedLoginAttempts gte 4> <!--- too many attempts, lock the account for 3 minutes to protect against brute force hacking --->
			<cfset this.update(lockedUntil=DateAdd("n", 2, utcNow()))>
		<cfelse>
			<cfset this.update(failedLoginAttempts=this.failedLoginAttempts+1)> <!--- password wrong, increment number of login attempts --->
		</cfif>
		<cfreturn false>
	</cffunction>


	<cffunction name="resetPassword" returntype="boolean" output="false">
		<cfset this.generatePasswordAndSalt()>
		<cfreturn this.update(lockedUntil="", failedLoginAttempts=0, mustChangePassword=1)>
	</cffunction>
	

	<cffunction name="generatePasswordAndSalt" returntype="void" output="false">
		<cfset var i = 0>
		<cfset this.password = "">
		<cfloop from="1" to="4" index="i">
			<cfset this.password = this.password & Mid("abcdefghijklmnopqrstuvwxyz", RandRange(1, 26), 1)>
			<cfset this.password = this.password & RandRange(1, 9)>
		</cfloop>
		<cfset this.passwordSalt = GenerateSecretKey("AES")>
	</cffunction>


	<cffunction name="saltAndHash" returntype="string" output="false">
		<cfargument name="password" type="string" default="#this.password#">
		<cfargument name="salt" type="string" default="#this.salt#">
		<cfset var loc = {}>
		<cfset loc.result = arguments.password>
		<cfloop from="1" to="#arguments.hashIterations#" index="loc.i">
			<cfset loc.result = Hash(loc.result & arguments.salt, "SHA-512")>
		</cfloop>
		<cfreturn loc.result>
	</cffunction>
	
	
</cfcomponent>
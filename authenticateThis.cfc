<cfcomponent displayname="Authenticate This" output="false" author="Andrew Bellenie" support="andybellenie@gmail.com">

	
	<!--- plugin config --->
	
	<cffunction name="init" output="false">
		<cfset this.version = "1.4,1.4.1,1.4.2,1.4.3,1.4.4,1.4.5">
		<cfreturn this>
	</cffunction>

	
	
	<!--- setup --->
	
	<cffunction name="authenticateThis" mixin="model">
		<cfargument name="required" type="boolean" default="true" hint="Whether or not a password is required.">
		<cfargument name="hashIterations" type="numeric" required="true" hint="I am the number of iterations of the salt/hash process. I should be big (1000+).">
		<cfargument name="hashAlgorithm" type="string" default="SHA-512" hint="I am the algorithm used for hashing the password.">
		<cfargument name="passwordProperty" type="string" default="password" hint="I am the name of the virtual property for the password.">
		<cfargument name="hashProperty" type="string" default="passwordHash" hint="I am the name of the persistent property for the hashed password.">
		<cfargument name="saltProperty" type="string" default="passwordSalt" hint="I am the name of the persistent property for the password salt.">
		<cfargument name="changeRequiredProperty" type="string" default="passwordChangeRequired" hint="I am the name of the property for forcing a password change.">
		<cfargument name="formatRegEx" type="string" default="^.*(?=.{8,})(?=.*\d)(?=.*[a-z]).*$" hint="I am a regular expression that enforces the format of the password.">
		<cfargument name="formatErrorMessage" type="string" default="Password must be at least 8 characters long and contain a mixture of numbers and letters" hint="I am the error message returned if the password is invalid.">
		<cfset variables.wheels.class.authenticateThis = Duplicate(arguments)>
		<cfif arguments.required>
			<cfset validatesPresenceOf(property=arguments.passwordProperty, when="onCreate")>
			<cfset validatesPresenceOf(property=arguments.passwordProperty, when="onUpdate", condition="StructKeyExists(this, 'updatePassword')")>
		</cfif>
		<cfset validatesFormatOf(property=arguments.passwordProperty, regEx=arguments.formatRegEx, message=arguments.formatErrorMessage, allowBlank=true)>
		<cfset validatesConfirmationOf(property=arguments.passwordProperty)>
		<cfset beforeValidation(methods="hashPassword")>
	</cffunction>
	
	
	
	<!--- accessors --->
	
	<cffunction name="$getHashIterations" returntype="numeric" output="false" mixin="model">
		<cfreturn variables.wheels.class.authenticateThis.hashIterations>
	</cffunction>


	<cffunction name="$getHashAlgorithm" returntype="string" output="false" mixin="model">
		<cfreturn variables.wheels.class.authenticateThis.hashAlgorithm>
	</cffunction>


	<cffunction name="$getPasswordProperty" returntype="string" output="false" mixin="model">
		<cfreturn variables.wheels.class.authenticateThis.passwordProperty>
	</cffunction>


	<cffunction name="$getHashProperty" returntype="string" output="false" mixin="model">
		<cfreturn variables.wheels.class.authenticateThis.hashProperty>
	</cffunction>


	<cffunction name="$getSaltProperty" returntype="string" output="false" mixin="model">
		<cfreturn variables.wheels.class.authenticateThis.saltProperty>
	</cffunction>


	<cffunction name="$getChangeRequiredProperty" returntype="string" output="false" mixin="model">
		<cfreturn variables.wheels.class.authenticateThis.changeRequiredProperty>
	</cffunction>
	
	
	
	<!--- callbacks --->

	<cffunction name="hashPassword" returntype="void" output="false" mixin="model">
		<cfif StructKeyExists(this, $getPasswordProperty())>
			<cfset this[$getSaltProperty()] = GenerateSecretKey("AES")>
			<cfset this[$getHashProperty()] = saltAndHash(this[$getPasswordProperty()], this[$getSaltProperty()])>
		</cfif>
	</cffunction>
	
	

	<!--- api --->

	<cffunction name="checkPassword" returntype="boolean" output="false">
		<cfargument name="password" type="string" required="true">
		<cfreturn CompareNoCase(this[$getHashProperty()], this.saltAndHash(arguments.password, this[$getSaltProperty()])) eq 0>
	</cffunction>


	<cffunction name="resetPassword" returntype="boolean" output="false">
		<cfset generateNewPassword()>
		<cfreturn update(validate=false)>
	</cffunction>
	

	<cffunction name="generateNewPassword" returntype="void" output="false">
		<cfargument name="length" type="numeric" default="12">
		<cfset var loc = {}>
		<cfset loc.range = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789">
		<cfset loc.result = ArrayNew(1)>
		<cfset ArrayAppend(loc.result, Mid(loc.range, RandRange(1, 26), 1))> <!--- 1 lowercase --->
		<cfset ArrayAppend(loc.result, Mid(loc.range, RandRange(27, 52), 1))> <!--- 1 uppercase --->
		<cfset ArrayAppend(loc.result, Mid(loc.range, RandRange(53, 62), 1))> <!--- 1 number --->
		<cfloop from="1" to="#arguments.length-3#" index="i">
			<cfset ArrayAppend(loc.result, Mid(loc.range, RandRange(1, 62), 1))>
		</cfloop>
		<cfset CreateObject("java", "java.util.Collections").Shuffle(loc.result)>
		<cfset this[$getPasswordProperty()] = ArrayToList(loc.result, "")>
		<cfset this[$getChangeRequiredProperty()] = true>
	</cffunction>


	<cffunction name="saltAndHash" returntype="string" output="false">
		<cfargument name="password" type="string" default="#this.password#">
		<cfargument name="salt" type="string" default="#this.salt#">
		<cfset var loc = {}>
		<cfset loc.result = arguments.password>
		<cfloop from="1" to="#$getHashIterations()#" index="loc.i">
			<cfset loc.result = Hash(loc.result & arguments.salt, $getHashAlgorithm())>
		</cfloop>
		<cfreturn loc.result>
	</cffunction>
	
	
</cfcomponent>

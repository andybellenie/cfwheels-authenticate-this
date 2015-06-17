<cfcomponent displayname="Authenticate This" output="false" author="Andy Bellenie" support="andybellenie@gmail.com">

	
	<!--- plugin config --->
	
	<cffunction name="init" output="false">
		<cfset this.version = "1.1,1.1.1,1.1.2,1.1.3,1.1.4,1.1.5,1.1.6,1.1.7,1.1.8,1.4">
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
		<cfargument name="formatErrorMessage" type="string" default="Your password must be at least 8 characters long and contain a mixture of numbers and letters" hint="I am the error message returned if the password is invalid.">
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
		<cfif not StructKeyExists(this, $getPasswordProperty())>
			<cfset this[$getPasswordProperty()] = "">
		</cfif>
		<cfif Len($getPasswordProperty()) and hasChanged($getPasswordProperty())>
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
		<cfset var i = 0>
		<cfset var keys = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789">
		<cfset this[$getPasswordProperty()] = "">
		<cfloop from="1" to="8" index="i">
			<cfset this[$getPasswordProperty()] = this[$getPasswordProperty()] & Mid(keys, RandRange(1, Len(keys)), 1)>
		</cfloop>
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

<cfcomponent displayname="Authenticate This" output="false" author="Andrew Bellenie" support="andybellenie@gmail.com">

	
	<!--- plugin config --->
	
	<cffunction name="init" output="false">
		<cfset this.version = "1.4,1.4.1,1.4.2,1.4.3,1.4.4,1.4.5">
		<cfreturn this>
	</cffunction>

	
	
	<!--- setup --->
	
	<cffunction name="authenticateThis" mixin="model">
		<cfargument name="required" type="boolean" default="true" hint="I am whether or not a password is required when creating/updating this model.">
		<cfargument name="workFactor" type="numeric" default="12" hint="I am the work factor for bCrypt.">
		<cfargument name="passwordProperty" type="string" default="password" hint="I am the name of the virtual property for the password.">
		<cfargument name="hashProperty" type="string" default="passwordHash" hint="I am the name of the persistent property for the hashed password.">
		<cfargument name="changeRequiredProperty" type="string" default="passwordChangeRequired" hint="I am the name of the property for forcing a password change.">
		<cfargument name="formatRegEx" type="string" default="^.*(?=.{8,})(?=.*\d)(?=.*[a-z]).*$" hint="I am a regular expression that enforces the format of the password.">
		<cfargument name="formatErrorMessage" type="string" default="Password must be at least 8 characters long and contain a mixture of numbers and letters" hint="I am the error message returned if the password is invalid.">
		<cfargument name="randomPasswordLength" type="numeric" default="12" hint="I am the default length of randomly generated passwords.">
		<cfset variables.wheels.class.authenticateThis = Duplicate(arguments)>
		<cfset variables.wheels.class.authenticateThis.bCrypt = CreateObject("java", "BCrypt", ExpandPath("/plugins/AuthenticateThis/"))>
		<cfif arguments.required>
			<cfset validatesPresenceOf(property=arguments.passwordProperty, when="onCreate")>
			<cfset validatesPresenceOf(property=arguments.passwordProperty, when="onUpdate", condition="StructKeyExists(this, 'updatePassword')")>
		</cfif>
		<cfset validatesFormatOf(property=arguments.passwordProperty, regEx=arguments.formatRegEx, message=arguments.formatErrorMessage, allowBlank=true)>
		<cfset validatesConfirmationOf(property=arguments.passwordProperty)>
		<cfset beforeValidation(methods="hashPassword")>
	</cffunction>



	<!--- callbacks --->

	<cffunction name="hashPassword" returntype="void" output="false" mixin="model">
		<cfset var settings = variables.wheels.class.authenticateThis>
		<cfif StructKeyExists(this, settings.passwordProperty)>
			<cfset this[settings.hashProperty] = settings.bCrypt.hashpw(this[settings.passwordProperty], settings.bCrypt.gensalt(settings.workFactor))>
		</cfif>
	</cffunction>
	
	

	<!--- api --->

	<cffunction name="checkPassword" returntype="boolean" output="false">
		<cfargument name="password" type="string" required="true">
		<cfset var settings = variables.wheels.class.authenticateThis>
		<cfreturn settings.bCrypt.checkpw(arguments.password, this[settings.hashProperty])>
	</cffunction>


	<cffunction name="resetPassword" returntype="boolean" output="false">
		<cfset var settings = variables.wheels.class.authenticateThis>
		<cfset this[settings.passwordProperty] = generateRandomPassword()>
		<cfset this[settings.changeRequiredProperty] = true>
		<cfreturn this.update(validate=false)>
	</cffunction>
	

	<cffunction name="generateRandomPassword" returntype="string" output="false">
		<cfset local.charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789">
		<cfset local.result = ArrayNew(1)>
		<cfset ArrayAppend(local.result, Mid(local.charset, RandRange(1, 26), 1))> <!--- 1 lowercase --->
		<cfset ArrayAppend(local.result, Mid(local.charset, RandRange(27, 52), 1))> <!--- 1 uppercase --->
		<cfset ArrayAppend(local.result, Mid(local.charset, RandRange(53, 62), 1))> <!--- 1 number --->
		<cfloop from="1" to="#variables.wheels.class.authenticateThis.randomPasswordLength-3#" index="i">
			<cfset ArrayAppend(local.result, Mid(local.charset, RandRange(1, 62), 1))>
		</cfloop>
		<cfset CreateObject("java", "java.util.Collections").Shuffle(local.result)>
		<cfreturn ArrayToList(local.result, "")>
	</cffunction>
	
	
</cfcomponent>

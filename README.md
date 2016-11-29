This solution contains a OWIN based federated login solution for sitecore. It's by no means production ready, but it might be an interesting
solution.

to install:

* add the following node to your connectionstrings.config:
```
<add name="AuthSessionStoreContext" providerName="System.Data.SqlClient" connectionString="Data Source=.\;Initial Catalog=WSFedTokens;Integrated Security=False;User ID=sa;Password=xxxxx;"/>
```
(don't forget to specify the name of your sql instance in the Data Source part of the connection string)
* it creates a new database when it's needed, login tokens will be stored in this database
* Create a controller rendering "Login" - Controller: "Auth" - Controller Action: "Index"
* Create a controller rendering "Logout" - Controller: "Auth" - Controller Action: "Logout"
* Create a page in the root called "Login" and place the login rendering on this page. - this page is used to login. It requires this path, because of some pipeline extension
* Create a page in the root called "Logout" and place the Logout rendering on this page. 
* Modify your startup.cs to include your own hostnames. If there is just one site, the pipeline branching is not needed
* Specify your Startup.cs for Owin to use: set the appsetting in web.config to point to it. I.e:
```
 <appSettings>
    <add key="owin:AppStartup" value="YourOwn.Project.Startup" />    
  </appSettings>
  ```
* If you are going to use WSFederation Auth, then you should probably set the requestValidationMode to 2.0 (or anything lower than 4.0) so that IIS doesn't stop the authentication process
due to a potentially dangerous Request.Form value error. For better security just set it to 2.0 on the path to your endpoint. I.e.:
```
  <location path="/login">
    <system.web>
      <httpRuntime requestValidationMode="2.0" />
    </system.web>
  </location>
```
* If there are any questions: please feel free to contact me.

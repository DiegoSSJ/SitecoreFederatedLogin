This solution contains an OWIN based federated login nuget package meant to be used in Sitecore. It's by no means production ready, but it might be an interesting
solution. 

The module will try to login users already existing in Sitecore as real users, and otherwise it'll create virtual users. Also, Sitecore logged users are
checked correctly.

To build:
* Create the Source for the Sitecore packages in Visual Studio
* Build

To install to your Sitecore implementation solution:
* Add the generated nuget package to it. Remove the Web.config file that is created in your project when doing that.
* Add the following node to your connectionstrings.config, and as needed per deployment environments:
```
<add name="AuthSessionStoreContext" providerName="System.Data.SqlClient" connectionString="Data Source=.\;Initial Catalog=WSFedTokens;Integrated Security=False;User ID=sa;Password=xxxxx;"/>
```
(don't forget to specify the name of your sql instance in the Data Source part of the connection string)
* it creates a new database when it's needed, login tokens will be stored in this database
* Create a controller rendering "Login" - Controller: "Auth" - Controller Action: "Index" and create a controller rendering "Logout" - Controller: "Auth" - Controller Action: "Logout". Or create appropiate routing for the '/login' and '/logout' paths, see https://doc.sitecore.net/sitecore_experience_platform/developing/developing_with_sitecore/mvc/use_mvc_routing
* Create a page in the root called "Login" and place the login rendering on this page. - this page is used to login. It requires this path, because of some pipeline extension
* Modify your startup.cs to include your own hostnames. If there is just one site, the pipeline branching is not needed. See example Startup.cs on this project.
* Specify your Startup.cs for Owin to use: set the appsetting in web.config to point to it. I.e:
```
 <appSettings>
    <add key="owin:AppStartup" value="YourOwn.Project.Startup" />    
  </appSettings>
  ```
* If you are going to use WSFederation Auth, and you still get errors regarding potentially dangerous Request.Form (i.e. because you set another endpoint than /login), then you can set the requestValidationMode to 2.0 (or anything lower than 4.0) so that IIS doesn't stop the authentication process
etter security just set it to 2.0 on the path to your endpoint. I.e.:
```
  <location path="/login">
    <system.web>
      <httpRuntime requestValidationMode="2.0" />
    </system.web>
  </location>
```
* Or you can add your ADFS auth endpoint return location to the form suppression class (SuppressADFSFormValidation.cs)
* Add the AuthenticationChecker and SuppressFormValidation pipelines:
```
 <sitecore>
    <pipelines>      
      <httpRequestBegin>
        <processor patch:after="*[@type='Sitecore.Pipelines.HttpRequest.UserResolver, Sitecore.Kernel']" type="SitecoreOwinFederator.pipelines.HttpRequest.AuthenticationChecker, SitecoreOwinFederator" />
      </httpRequestBegin>
            <preprocessRequest>
        <processor patch:instead="*[@type='Sitecore.Pipelines.PreprocessRequest.SuppressFormValidation, Sitecore.Kernel']" type="SitecoreOwinFederator.pipelines.PreprocessRequest.SuppressAdfsFormValidation, SitecoreOwinFederator" />
      </preprocessRequest>
    </pipelines>
```
* You can specify that the authenticator module return your users to the original path on the site they were at by using the Sitecore setting ADFS.Authenticator.RedirectToCurrentLocation
* You can specify roles for which users beloging to will be redirected to the EE editor for edition (param sc_mode=edit). Use the Sitecore setting ADFS.Authenticator.RolesToRedirectToEdit. Roles are pipe (|) separated. 
* Examples for both settings:
```
 <setting name="ADFS.Authenticator.RedirectToCurrentLocation" value="true" />
 <setting name="ADFS.Authenticator.RolesToRedirectToEdit" value="yourdomain\yourrole|yourdomain\anotherole" />
```
* If there are any questions: please feel free to contact me (diegossj or the original repo owner, Bas Lijten)

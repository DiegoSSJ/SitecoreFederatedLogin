using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using Microsoft.Owin.Security;
using Sitecore;
using Sitecore.Diagnostics;
using SitecoreOwinFederator.Authenticator;
using SitecoreOwinFederator.Pipelines.HttpRequest;

namespace SitecoreOwinFederator.sitecore_modules.shell.federation
{
  public partial class login : System.Web.UI.Page
  {
    private const string StartUrl = "/sitecore/shell/default.aspx";
    protected void Page_Load(object sender, EventArgs e)
    {
      var domain = Sitecore.Context.Domain;

      //var properties = new AuthenticationProperties();
      Log.Debug("In SitecoreOWIN ADFSAuth: Before challenge");
      Log.Debug("OWIN Context authentication type: " + HttpContext.Current.GetOwinContext().Authentication.GetType());
      var OwinContext = HttpContext.Current.GetOwinContext();
      var OwinAuth = OwinContext.Authentication;
      foreach (var authenticationDescription in OwinAuth.GetAuthenticationTypes())
      {
        Log.Debug("OWIN Context authentication types: " + authenticationDescription.AuthenticationType);
        foreach (var authenticationDescriptionProperty in authenticationDescription.Properties)
        {
          Log.Debug("OWIN Context authentication type property:" + authenticationDescriptionProperty.Key + " " + authenticationDescriptionProperty.Value);
        }
      }


      HttpContext.Current.GetOwinContext().Authentication.Challenge();
      //HttpContext.Current.GetOwinContext().Authentication.AuthenticateAsync()
      var chaResp = OwinAuth.AuthenticationResponseChallenge;
      Log.Debug("ADFAuth challenge response" + chaResp);
      var user = OwinAuth.User;
      Log.Debug("ADFAuth user : " + user);
      Log.Debug("In SitecoreOWIN ADFSAuth: After challenge");

      var principal = IdentityHelper.GetCurrentClaimsPrincipal();

      // Login the sitecore user with the claims identity that was provided by identity ticket
      LoginHelper loginHelper = new LoginHelper();
      loginHelper.Login(principal);
      //else
      //{
      //    var returnUrl = HttpUtility.ParseQueryString(ctx.QueryString.ToString()).Get("returnUrl");
      //    if (returnUrl.Contains("sitecore/shell"))
      //        returnUrl = StartUrl;
      //    //WriteCookie("sitecore_starturl", StartUrl);
      //    //WriteCookie("sitecore_starttab", "advanced");
      //    Response.Redirect(returnUrl);
      //}            
    }
  }
}
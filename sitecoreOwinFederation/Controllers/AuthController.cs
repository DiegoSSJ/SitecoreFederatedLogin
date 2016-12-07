using System;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using Microsoft.Owin.Security;
using Sitecore;
using Sitecore.Analytics;
using Sitecore.Configuration;
using Sitecore.Diagnostics;
using Sitecore.Security.Authentication;
using Sitecore.StringExtensions;
using Sitecore.Web;
using Sitecore.Web.Authentication;
using SitecoreOwinFederator.Authenticator;
using SitecoreOwinFederator.Pipelines.HttpRequest;

namespace SitecoreOwinFederator.Controllers
{
  /// <summary>
  /// Authentication controller, contains login and logout functionality.
  /// THe authorize attribute on the Index Action forces OWIN to trigger an ASP.Net authenticaiton challenge
  /// </summary>
  public class AuthController : Controller
  {
    // GET: Auth
    [Authorize]
    public ActionResult Index()
    {
      Log.Debug("ADFSAuth AuthController Index");

      // Get ID ticket from .ASP.Net cookie. This ticket doesnt contain an identity, 
      // but a reference to the identity in the Session Store                          
      var principal = IdentityHelper.GetCurrentClaimsPrincipal();

      System.Web.HttpContext.Current.GetOwinContext().Authentication.Challenge();
      Log.Debug("ADFSAuth Owin user name: " + System.Web.HttpContext.Current.GetOwinContext().Authentication.User.Identity.Name);

      var ctx = Tracker.Current.Session;
      // Login the sitecore user with the claims identity that was provided by identity ticket
      LoginHelper loginHelper = new LoginHelper();
      loginHelper.Login(principal);

      Log.Debug("ADFSAuth: After log in in AuthController, user is " + Context.User.GetLocalName());
      Log.Debug("ADFSAuth: After log in Owin user name: " + System.Web.HttpContext.Current.GetOwinContext().Authentication.User.Identity.Name);

      System.Web.HttpContext.Current.User = Sitecore.Context.User;
      ctx = Tracker.Current.Session;

      // temporary code to show user claims, while there is a sitecore user object as
      //UserClaimsModel ucm = new UserClaimsModel();
      //ucm.Claims = ((ClaimsPrincipal)principal).Claims;
      //return View(ucm);
      string redirect = "/";
      if (Settings.GetBoolSetting(Constants.RedirectToCurrentLocationSettingName,false)
        && !WebUtil.GetCookieValue(Constants.AdfsCurrentPathSaveCookieName).IsNullOrEmpty() &&
          !WebUtil.GetCookieValue(Constants.AdfsCurrentPathSaveCookieName).Contains("logout"))
      {
        Log.Debug("ADFSAuth: In AuthController login, found adfsSavePath cookie with value: " + WebUtil.GetCookieValue(Constants.AdfsCurrentPathSaveCookieName));
        redirect = WebUtil.GetCookieValue(Constants.AdfsCurrentPathSaveCookieName);
      }

      string rolesToRedirectToEdit = Settings.GetSetting(Constants.RolesToRedirectToEditSettingName, "");
      Log.Debug("ADFSAuth: In AuthController login, rolesToRedirectToEdit is :" + rolesToRedirectToEdit);
      if (!rolesToRedirectToEdit.IsNullOrEmpty() &&
          rolesToRedirectToEdit.Split('|').Any(role => Context.User.IsInRole(role)))
      {
        Log.Debug("ADFSAuth: In AuthController login, user matched roles to redirect to edit");
        redirect += Constants.SitecoreStartEditingParameter;
      }        

      Log.Debug("ADFSAuth: In AuthController login, redirecting to " + redirect);
      return Redirect(redirect);
    }

    /// <summary>
    /// Logs out user 
    /// </summary>
    /// <returns></returns>
    public ActionResult Logout()
    {
      Log.Debug("ADFSAuth AuthController Logout");

      if (Request.IsAuthenticated)
      {
        string redirect = "/";
        if (!WebUtil.GetCookieValue(Constants.AdfsCurrentPathSaveCookieName).IsNullOrEmpty() && Settings.GetBoolSetting(Constants.RedirectToCurrentLocationSettingName, false))
          redirect = WebUtil.GetCookieValue(Constants.AdfsCurrentPathSaveCookieName);

        AuthenticationProperties properties = new AuthenticationProperties();
        
        properties.RedirectUri = "https://" + Context.Site.TargetHostName + redirect;        
        properties.AllowRefresh = false;
        AuthenticationManager.Logout();
        foreach (AuthenticationProvider authenticationProvider in AuthenticationManager.Providers)
        {
          Log.Debug("ADFSAuth: Logging out user " + Context.User.Name + " in provider: " + authenticationProvider.Name);
          authenticationProvider.Logout();
        }

        // Log out from Sitecore for real as we are using real users
        Session.Abandon();
        if (!TicketManager.GetCurrentTicketId().IsNullOrEmpty())
          TicketManager.RemoveTicket(TicketManager.GetCurrentTicketId());
        WebUtil.SetCookieValue(Constants.SitecoreUserTicketCookieName, "",DateTime.Now.AddDays(-1));

        Request.GetOwinContext().Authentication.SignOut(properties);
        
        Log.Debug("ADFSAuth: In AuthController logout, redirecting to " + redirect);
        return Redirect(redirect);

      }
      return Redirect("/");
    }
  }


}
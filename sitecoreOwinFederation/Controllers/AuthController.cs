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
using Sitecore.Sites;
using Sitecore.StringExtensions;
using Sitecore.Web;
using Sitecore.Web.Authentication;
using SitecoreOwinFederatorLiU.Pipelines.HttpRequest;

namespace SitecoreOwinFederatorLiU.Controllers
{
  /// <summary>
  /// Authentication controller, contains login and logout functionality.
  /// THe authorize attribute on the Index Action forces OWIN to trigger an ASP.Net authenticaiton challenge
  /// </summary>
  public class AuthController : Controller
  {
    // GET: Auth
    [Authorize]
    //public ActionResult Index(string sc_itemid, string sc_lang, string sc_db, string sc_device, string sc_mode, string sc_debug, string sc_trace, string sc_prof, string sc_ri, string sc_rb)
    //public ActionResult Index(string[] parameters)
    //{
    //  Log.Info("SitecoreOwin Login with string[]",this);
    //  //WebUtil.SetCookieValue(Constants.AdfsCurrentPathSaveCookieName, returnUrl);
    //  return Index();
    //}

    //// GET: Auth
    //[Authorize]
    //public ActionResult Index(string returnUrl)
    //{
    //  Log.Debug("SitecoreOwin Login with returnUrl");
    //  WebUtil.SetCookieValue(Constants.AdfsCurrentPathSaveCookieName, returnUrl);
    //  return Index();
    //}

    // GET: Auth
    [Authorize]
    //public ActionResult Index()
    public ActionResult Index(string[] parameters)
    {
      Log.Debug("SitecoreOwin AuthController Index");

      try
      {

        System.Web.HttpContext.Current.GetOwinContext().Authentication.Challenge();
        Log.Debug("SitecoreOwin Owin user name: " +
                  System.Web.HttpContext.Current.GetOwinContext().Authentication.User.Identity.Name);

        var ctx = Tracker.Current?.Session;
        // Login the sitecore user with the claims identity that was provided by identity ticket
        LoginHelper loginHelper = new LoginHelper();
        loginHelper.Login(System.Web.HttpContext.Current.User.Identity);

        Log.Debug("SitecoreOwin: After log in in AuthController, user is " + Context.User.GetLocalName());
        Log.Debug("SitecoreOwin: After log in Owin user name: " +
                  System.Web.HttpContext.Current.GetOwinContext().Authentication.User.Identity.Name);

        System.Web.HttpContext.Current.User = Context.User;

        ctx = Tracker.Current?.Session;

        // temporary code to show user claims, while there is a sitecore user object as
        //UserClaimsModel ucm = new UserClaimsModel();
        //ucm.Claims = ((ClaimsPrincipal)principal).Claims;
        //return View(ucm);
        string redirect = "/";
        if (Settings.GetBoolSetting(Constants.RedirectToCurrentLocationSettingName, false)
          && !WebUtil.GetCookieValue(Constants.AdfsCurrentPathSaveCookieName).IsNullOrEmpty() &&
            !WebUtil.GetCookieValue(Constants.AdfsCurrentPathSaveCookieName).Contains("logout"))
        {
          Log.Debug("SitecoreOwin: In AuthController login, found adfsSavePath cookie with value: " + WebUtil.GetCookieValue(Constants.AdfsCurrentPathSaveCookieName));
          redirect = WebUtil.GetCookieValue(Constants.AdfsCurrentPathSaveCookieName);
        }

        string rolesToRedirectToEdit = Settings.GetSetting(Constants.RolesToRedirectToEditSettingName, "");
        Log.Debug("SitecoreOwin: In AuthController login, rolesToRedirectToEdit is :" + rolesToRedirectToEdit);
        if (!rolesToRedirectToEdit.IsNullOrEmpty() &&
            rolesToRedirectToEdit.Split('|').Any(role => Context.User.IsInRole(role)))
        {
          Log.Debug("SitecoreOwin: In AuthController login, user matched roles to redirect to edit");
          redirect += Constants.SitecoreStartEditingParameter;
        }

        Log.Debug("SitecoreOwin: In AuthController login, redirecting to " + redirect);
        return Redirect(redirect);
      }
      catch (Exception e)
      {
        Log.Error("SitecoreOwin error in login: " + e.Message, e);
        throw;
      }
    }

    /// <summary>
    /// Logs out user 
    /// </summary>
    /// <returns></returns>
    public ActionResult Logout()
    {
      Log.Debug("SitecoreOwin AuthController Logout");

      // Change mode to normal to avoid being redirected to Sitecore loggin all the time. 
      Context.Site.SetDisplayMode(DisplayMode.Normal, DisplayModeDuration.Remember);

      if (Request.IsAuthenticated)
      {
        Log.Audit("SitecoreOwin: Logging out user " + Context.User.Name, this);

        string redirect = "/";
        if (!WebUtil.GetCookieValue(Constants.AdfsCurrentPathSaveCookieName).IsNullOrEmpty() && Settings.GetBoolSetting(Constants.RedirectToCurrentLocationSettingName, false))
          redirect = WebUtil.GetCookieValue(Constants.AdfsCurrentPathSaveCookieName);

        AuthenticationProperties properties = new AuthenticationProperties();


        properties.RedirectUri = "https://" + Context.Site.TargetHostName + redirect;
        properties.AllowRefresh = false;
        AuthenticationManager.Logout();
        foreach (AuthenticationProvider authenticationProvider in AuthenticationManager.Providers)
        {
          Log.Debug("SitecoreOwin: Logging out user " + Context.User.Name + " in provider: " + authenticationProvider.Name);
          authenticationProvider.Logout();
        }

        // Log out from Sitecore for real as we are using real users
        Session.Abandon();
        if (!TicketManager.GetCurrentTicketId().IsNullOrEmpty())
          TicketManager.RemoveTicket(TicketManager.GetCurrentTicketId());
        WebUtil.SetCookieValue(Constants.SitecoreUserTicketCookieName, "", DateTime.Now.AddDays(-1));

        Log.Debug("SitecoreOwin: In AuthController logout, redirecting to " + redirect);
        return Redirect(redirect);

      }
      return Redirect("/");
    }
  }


}
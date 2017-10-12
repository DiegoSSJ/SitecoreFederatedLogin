using System;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using Microsoft.Owin.Security;
using Sitecore;
using Sitecore.Analytics;
using Sitecore.Configuration;
using Sitecore.Diagnostics;
using Sitecore.Sites;
using Sitecore.StringExtensions;
using Sitecore.Web;
using SitecoreOwinFederatorLiU.Pipelines.HttpRequest;
using Sitecore.Pipelines;
using Sitecore.Pipelines.Logout;

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
    public ActionResult Index(string[] parameters)
    {
      Log.Debug("SitecoreOwin AuthController Index");

        // Is Callback from Sitecore's logout, check user and do logout instead 
      var fromSitecoreLogoutPipeline = HttpContext?.Request?.Params?.Get(Constants.LogoutFromSitecorePipelineParameterName);
      if (!fromSitecoreLogoutPipeline.IsNullOrEmpty() && fromSitecoreLogoutPipeline.ToLower().Equals("true"))
      {
        Log.Debug("SitecoreOwing AuthController Index: Logging out user after callback from Sitecore's logout pipeline");
        return Redirect(Constants.LogoutFromSitecoreAndSitecorePipelinePath);
      }

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

        if (!Request.Params.Get("returnUrl").IsNullOrEmpty())
        {
          Log.Debug("SitecoreOwin: In AuthController login, found returnUrl request, using it instead of anything else");
          redirect = Request.Params.Get("returnUrl");
        }

        string rolesToRedirectToEdit = Settings.GetSetting(Constants.RolesToRedirectToEditSettingName, "");
        Log.Debug("SitecoreOwin: In AuthController login, rolesToRedirectToEdit is :" + rolesToRedirectToEdit);
        if (!rolesToRedirectToEdit.IsNullOrEmpty() &&
            rolesToRedirectToEdit.Split('|').Any(role => Context.User.IsInRole(role)) &&
            !redirect.Contains(Constants.SitecoreStartEditingParameter))
        {
          string useParameterEditMode = Settings.GetSetting(Constants.UseParameterEditMode, "False");
          Log.Debug("SitecoreOwin: In AuthController login, useParameterEditMode is " + useParameterEditMode);
          if (useParameterEditMode.IsNullOrEmpty() || useParameterEditMode.ToLower().Equals("false"))
            Context.Site.SetDisplayMode(DisplayMode.Edit, DisplayModeDuration.Remember);
          else            
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


      var redirect = GetRedirectTo();
      var fromTransfer = HttpContext?.Request?.Params?.Get(Constants.LogoutTransferParameterName);
      // Specifik till utloggning från Sitecore, fungerar inte ändå. Vi vill att sidan ska laddas om efter utloggningen, men det 
      // fungerar inte. 
      if ( !fromTransfer.IsNullOrEmpty() && fromTransfer.ToLower().Equals("true"))
      {
        Log.Debug("SitecoreOwin: Tranferring to " + redirect);
        //Server.Transfer(redirect); // doesn't work
        //Server.TransferRequest(redirect);
        //Response.Redirect("/");
        Response.Clear();
        string responseText = Constants.DocumentLocationReloadHtml.Replace("\n", System.Environment.NewLine).Replace("#*#*", Request.Url.GetLeftPart(UriPartial.Authority) + redirect);        
        Response.Output.Write(responseText);
        //Response.Redirect("/", true);        
        Response.End();
        //Response.RedirectLocation =         
        //Response.RedirectLocation = "/?hehe=true";
        return null;

      }

      // Gör utloggningen via Sitecore's utloggningspipelines först, sedan i Owin
      var fromSitecoreLogoutPipeline = HttpContext?.Request?.Params?.Get(Constants.LogoutFromSitecorePipelineParameterName);
      if (fromSitecoreLogoutPipeline.IsNullOrEmpty() || !fromSitecoreLogoutPipeline.Equals("true"))
      {
        Log.Audit("SitecoreOwin: logging out user " + Context.User.Name + " from Sitecore", this);
        var logoutArgs = new LogoutArgs();
        logoutArgs.RedirectUrl = new Sitecore.Text.UrlString(Constants.LogoutFromSitecorePipelinePath);
        try
        {
          Log.Debug("SitecoreOwin: trying to log out user from Sitecore via Content Editor logout pipeline");
          CorePipeline.Run("logout", logoutArgs);
        }
        catch (InvalidOperationException ioe)
        {
          Log.Debug("SitecoreOwin: trying to log out user from Sitecore via EE logout pipeline");
          CorePipeline.Run("speak.logout", logoutArgs);
        }

        Log.Debug("SitecoreOwin: logged out user from Sitecore, proceeding with Owin logout");
        return Redirect(Constants.LogoutFromSitecorePipelinePath);
      }


      // Change mode to normal to avoid being redirected to Sitecore loggin all the time. 
      Context.Site.SetDisplayMode(DisplayMode.Normal, DisplayModeDuration.Remember);




      // Utloggad från Sitecore, men fortfarande inloggad via ADFS. Logga ut från ADFS via Owin. 
      if (Request.IsAuthenticated)
      {

        Log.Audit("SitecoreOwin: Logging out user " + Context.User.Name + " from Owin", this);
        if (redirect.Contains(Constants.SitecoreStartEditingParameter))
          redirect = redirect.Replace(Constants.SitecoreStartEditingParameter, "");

        

        if (redirect.IndexOf(Constants.LogoutPath) == 0)
          redirect = "/";

        var fromSitecoreLogout = HttpContext?.Request?.Params?.Get(Constants.LogoutFromSitecoreParameterName);
        if (!fromSitecoreLogout.IsNullOrEmpty() && fromSitecoreLogout.ToLower().Equals("true"))
        {
          // Vi loggade ut från Sitecore istället för vår utloggning, försök ladda om sidan i nästa steg (fungerar tyvärr inte än)
          redirect = Constants.LogoutTransferPath + Uri.EscapeDataString(redirect);
        }

        Log.Debug("SitecoreOwin: In AuthController logout, redirecting to from Owin Logout " + redirect);
        // Sign out from OWIN - redirect to current page
        var owinContext = Request.GetOwinContext();
        var authProperties = new AuthenticationProperties();
        authProperties.RedirectUri = HttpContext.Request.Url.GetLeftPart(UriPartial.Authority) + redirect;
        owinContext.Authentication.SignOut(authProperties);
      }

      return Redirect(redirect);
    }


    private string GetRedirectTo ()
    {
      string redirect = "/";
      if (!WebUtil.GetCookieValue(Constants.AdfsCurrentPathSaveCookieName).IsNullOrEmpty() && Settings.GetBoolSetting(Constants.RedirectToCurrentLocationSettingName, false))
        redirect = WebUtil.GetCookieValue(Constants.AdfsCurrentPathSaveCookieName);

      if (!Request.Params.Get(Constants.SitecoreReturnUrlParameterName).IsNullOrEmpty())
      {
        Log.Debug("SitecoreOwin: In AuthController logout, found returnUrl request, using it instead of anything else");
        redirect = Request.Params.Get("returnUrl");
      }
      return redirect;
    }
  }
}



using System.Security.Claims;
using System.Web;
using System.Web.Mvc;
using Microsoft.Owin.Security;
using Sitecore.Analytics;
using Sitecore.Diagnostics;
using Sitecore.Security.Authentication;
using SitecoreOwinFederator.Authenticator;
using SitecoreOwinFederator.Models;
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

      var ctx = Tracker.Current.Session;
      // Login the sitecore user with the claims identity that was provided by identity ticket
      LoginHelper loginHelper = new LoginHelper();
      loginHelper.Login(principal);

      ctx = Tracker.Current.Session;

      // temporary code to show user claims, while there is a sitecore user object as
      //UserClaimsModel ucm = new UserClaimsModel();
      //ucm.Claims = ((ClaimsPrincipal)principal).Claims;
      //return View(ucm);
      return Redirect("/");
    }

    /// <summary>
    /// Logs out user 
    /// </summary>
    /// <returns></returns>
    public ActionResult Logout()
    {
      Log.Debug("ADFSAuth AuthController Logout");

      AuthenticationProperties properties = new AuthenticationProperties();
      properties.RedirectUri = "/login";
      properties.AllowRefresh = false;
      AuthenticationManager.Logout();
      Request.GetOwinContext().Authentication.SignOut(properties);
      //return View();
      return Redirect("/");
    }
  }


}
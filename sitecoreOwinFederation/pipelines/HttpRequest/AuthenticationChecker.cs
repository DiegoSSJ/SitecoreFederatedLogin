using System;
using System.Security.Claims;
using System.Web;
using System.Web.Security;
using Sitecore;
using Sitecore.Configuration;
using Sitecore.Diagnostics;
using Sitecore.Pipelines.HttpRequest;
using Sitecore.Security.Authentication;
using Sitecore.Sites;
using Sitecore.StringExtensions;
using Sitecore.Text;
using Sitecore.Web;
using SitecoreOwinFederator.Authenticator;
using SitecoreOwinFederator.Pipelines.HttpRequest;

namespace SitecoreOwinFederator.pipelines.HttpRequest
{
  /// <summary>
  /// Verifies authentication tickets:
  /// If .AspxAuth is available and no .AspNet.Cookies: deny permission, logout and redirect to login
  /// If .AspNet.Cookies is available and no .AspxAuth: login sitecore user
  /// If both are unavailable: anonymous user
  /// If both are available:
  ///     Check identities: if they are equal: OK
  ///     Else: logout both identities and redirect to a public page
  /// </summary>
  public class AuthenticationChecker : HttpRequestProcessor
  {
    public override void Process(HttpRequestArgs args)
    {
      Assert.ArgumentNotNull(args, "args");
      var sitecoreUserLoggedIn = Context.IsLoggedIn;
      string key = String.Empty;
      ClaimsPrincipal federatedUser = null;
      key = IdentityHelper.GetAuthTokenFromCookie();
      Log.Debug("ADFSAuth: In AuthChecker. Domain is " + Context.Domain.Name);

    
      //HttpContext.Current.Response.Cookies.Set(new HttpCookie("adfsSavedPath", HttpContext.Current.Request.Path));      
      //if (Context.Item != null)
      //  WebUtil.SetCookieValue(Constants.adfsCurrentPathSaveCookieName, LinkManager.GetItemUrl(Context.Item));      
      if (!HttpContext.Current.Request.Path.Contains("/-/") && !HttpContext.Current.Request.Path.Contains("~")
          && !HttpContext.Current.Request.Path.Contains(".") && !HttpContext.Current.Request.Path.Contains("/sitecore/") &&
          !HttpContext.Current.Request.Path.Contains("/shell/") &&
          !HttpContext.Current.Request.Path.Contains("/login") &&
          ((HttpContext.Current.Request.UrlReferrer != null && 
          !HttpContext.Current.Request.UrlReferrer.AbsoluteUri.Contains("wtrealm")) ||
          (HttpContext.Current.Request.UrlReferrer == null )))
      {
        Log.Debug("ADFSAuth: Writing location cookie to " + HttpContext.Current.Request.RawUrl);
        WebUtil.SetCookieValue(Constants.AdfsCurrentPathSaveCookieName, HttpContext.Current.Request.RawUrl);
      }        

      // only check if domain is not equal to the sitecore domain
      // TODO: can be removed if we are logging in with claims as well for editors
      //if (!Context.Domain.Name.Equals("sitecore") || !( Context.IsLoggedIn && Context.User.Domain.Name.Equals("sitecore")) )
      //if (HttpContext.Current.Request.IsAuthenticated)
      //{
        federatedUser = IdentityHelper.GetCurrentClaimsPrincipal() as ClaimsPrincipal;

        // algorithm:
        // 1 - if user is not logged in AND claimscookie is missing, return: anonymous visit -> handle in pipeline
        // 2 - if only claimscookie is available, delete this cookie -> handled by owin
        // 3 - if only ID in Database is available (not possible to check) -> handled by timer
        // 4 - if cookie, fedID and no sitecore ID is available -> redirect to login page, handled by sitecore
        // 5 - if only .ASPXAUTH cookiue is available (Context.IsLoggedIn) -> logout and redirect -> pipeline
        // 6 - if claimscookie, no fed ID and sitecore login is availalbe: logout and redirect -> pipeline
        // 7-  if no claimscookie, no fed ID and sitecore login available: logout and redirect -> pipeline. 
        // handled by  

        Log.Debug("ADFAuth: In AuthChecker. User is logged in: " + Context.IsLoggedIn + " key: " + key + " federatedUser: " + (federatedUser != null ? federatedUser.Identity.Name : "null"));



        // 1 - anonymous
        if (!Context.IsLoggedIn && String.IsNullOrEmpty(key))
          return;
        // 5 & 7 - pipeline if user is logged in
        else if (Context.IsLoggedIn && String.IsNullOrEmpty(key))
        {
          // Logged in from Sitecore 
          if (Context.IsLoggedIn && Context.User.Domain.Name.Equals("sitecore"))
            return;
          LogoutAndRedirectToLogoutPage();
        }


        // 6 - pipeline 
        else if (!String.IsNullOrEmpty(key) && Context.IsLoggedIn && federatedUser == null)
        {
          LogoutAndRedirectToLogoutPage();
        }

        // 8 all identities available
        // check if identity matches.
        // if not: redirect. Otherwise: return
        else if (!String.IsNullOrEmpty(key) && Context.IsLoggedIn && federatedUser != null)
        {
          var user = Context.User;
          Log.Debug("ADFSAuth in AuthChecker: Case 8. user name: " + user.Name + " federated name: " + federatedUser.Identity.Name);

          // compare identities
          // if not equal, , there is a cookie mismatch: 
          //      remove tokens, 
          //      logout sitecore user and 
          //      redirect to loginpage.          
          // do not compare domain as the domain can sometimes not match. or take the domain from the claim -> better for multisites
          string customName = CustomGetNameFromClaims(federatedUser.Identity as ClaimsIdentity);
          Log.Debug("ADFSAuth in AuthChecker - customName is " + customName);
          if (
            !user.Name.ToLower()
              .Equals(customName.IsNullOrEmpty() ? federatedUser.Identity.Name.ToLower() : customName.ToLower()))
          {
            Log.Debug("ADFSAuth: user name and federated name did not match, log in out user");
            LogoutAndRedirectToLogoutPage();
          }
          else return;

          if (customName != null)
          {
            Log.Debug("ADFSAuth " + this.GetType().DeclaringMethod.Name + ": CustomName is " + customName + " relogging user as that");
            Log.Debug("ADFSAuth  is forms enabled: " + FormsAuthentication.IsEnabled);
            AuthenticationManager.SetActiveUser(customName);
            LoginHelper loginHelper = new LoginHelper();
            loginHelper.Login(federatedUser);
          }
        //}
        // several options:
        // Callback from the federated Identity provider, or an unexpected situation
        //else
        //{
          // Callback from the identity provider
          // entry from /login, auth context
          Log.Debug("ADFSAuth in AuthChecker: Unexpected callback");


          if (HttpContext.Current.Request.Url.PathAndQuery.StartsWith("/login",
            StringComparison.InvariantCultureIgnoreCase))
          {
            Log.Debug("ADFSAuth: Callback to login, not doing anything");
            return;
          }


          // For all other situations:
          //Log to database for other situation
          Log.Debug("ADFSAuth: logging out");
          LogoutAndRedirectToLogoutPage();
        //}
      }
    }
    private void LogoutAndRedirectToLogoutPage()
    {
      Log.Debug("ADFSAuth: Logging out and redirecting to logout page");
      string logoutPage = "/logout";
      AuthenticationManager.Logout();
      // Owin.Authentication.Logout does not work in pipeline: need to have an OWIN context: redirect to logout then.
      WebUtil.Redirect(logoutPage, false);
    }

    private void RedirectToLoginPage()
    {
      string loginPage = this.GetLoginPage(Context.Site);
      if (loginPage.Length > 0)
      {
        Log.Debug("ADFSAuth: Redirecting to login page");
        Tracer.Info("Redirecting to login page \"" + loginPage + "\".");
        UrlString urlString = new UrlString(loginPage);
        if (Settings.Authentication.SaveRawUrl)
        {
          urlString.Append("url", HttpUtility.UrlEncode(Context.RawUrl));
        }
        WebUtil.Redirect(urlString.ToString(), false);
      }
      else
      {
        Log.Debug("ADFSAuth: Redirecting to error page as no login page was found");
        Tracer.Info("Redirecting to error page as no login page was found.");
        WebUtil.RedirectToErrorPage("Login is required, but no valid login page has been specified for the site (" + Context.Site.Name + ").", false);
      }
    }

    protected virtual string GetLoginPage(SiteContext site)
    {
      if (site == null)
      {
        return string.Empty;
      }
      if (site.DisplayMode == DisplayMode.Normal)
      {
        return site.LoginPage;
      }
      SiteContext site2 = SiteContext.GetSite("shell");
      if (site2 != null)
      {
        return site2.LoginPage;
      }
      return string.Empty;
    }

    public virtual string CustomGetNameFromClaims(ClaimsIdentity identity)
    {
      return null;
    }
  }
}
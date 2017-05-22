#region
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Web;
using Sitecore;
using Sitecore.Analytics;
using Sitecore.Configuration;
using Sitecore.Diagnostics;
using Sitecore.Security.Accounts;
using Sitecore.Security.Authentication;
using Sitecore.StringExtensions;
using Sitecore.Web.Authentication;

#endregion

namespace SitecoreOwinFederator.Pipelines.HttpRequest
{
  public class LoginHelper
  {
    /// <summary>
    /// Logins the specified user.
    /// </summary>
    /// <param name="principal">The user.</param>
    public void Login(IPrincipal principal)
    {
      Log.Debug("SitecoreOwin: In LoginHelper");

      var identity = principal.Identity;
      var allowLoginToShell = false;
#region basic debug output (auth provider, identity, is authenticated, claims, liu id)
#if DEBUG
      Log.Debug("Authentication provider: " + AuthenticationManager.Provider.Description, this);
      Log.Debug(string.Format("Identity name: {0} ", identity.Name), this);

      Log.Debug(string.Format("Is authenticated: {0} ", identity.IsAuthenticated), this);
      WriteClaimsInfo(principal.Identity as ClaimsIdentity);
      Log.Debug("User's liu-id: " + GetLiUIdFromClaims(principal.Identity as ClaimsIdentity));
#endif
#endregion   

      if (!identity.IsAuthenticated)
        return;




      var liuId = GetLiUIdFromClaims(principal.Identity as ClaimsIdentity);
      if (string.IsNullOrEmpty(liuId))
        throw new IdentityNotMappedException();
      

      var userName = string.Format("{0}\\{1}", Context.Domain.Name, liuId.IsNullOrEmpty() ?  identity.Name : liuId);
      
      Log.Debug("SitecoreOwin: userName is " + userName + " Domain is : " + Context.Domain.Name);
      try
      {
        if (User.Exists(userName))
        {
          var realUser = User.FromName(userName, true);

          Boolean loginResult = AuthenticationManager.Login(realUser);
          // Behövs så att TicketManager körs, via allowLogintoShell = true
          Boolean loginResult2 = AuthenticationManager.Login(userName, !Settings.Login.DisableRememberMe, true);
          Log.Debug("ADFS: Logging user with persist: " + !Settings.Login.DisableRememberMe, this);         

          if (loginResult && loginResult2)
          {
            
            Log.Audit("ADFS: User " + userName + " authenticated and logged in as existing user in Sitecore", this);
            var profile = Context.User.Profile;            

            if (profile != null)
            {
              // Vi vill helst göra så här, men eftersom Sitecore har ingenting på sv-SE (tömma strängar överallt alltså)
              // och den tar sv-Se (från webbläsaren?) som default när profilen är default och shell#lang lämnas töm, 
              // då måste vi under tiden sätta engelska som default om profilen säger default. Detta pga av vi verkar inte
              // kunna sätta töm kaka här eftersom Sitecore får InvalidOperationException då. Det enda alternativet är att 
              // inte sätta kakan alls, då blir sv-SE. 
              /*if (!string.IsNullOrEmpty(Context.User.Profile.ClientLanguage))
                  AddOrUpdateSessionCookie("shell#lang", Sitecore.Context.User.Profile.ClientLanguage);*/
              if (profile.ClientLanguage != null)
                AddOrUpdateSessionCookie("shell#lang", profile.ClientLanguage.IsNullOrEmpty()
                  ? "en"
                  : profile.ClientLanguage);
              if (!string.IsNullOrEmpty(Context.User.Profile.StartUrl))
                AddOrUpdateSessionCookie("sitecore_starturl", Sitecore.Context.User.Profile.StartUrl);
            }
          }

          else Log.Info("ADFS: User " + userName + " failed to log in as existing user in Sitecore", this);
        }
        #region virtual user log in
        else
        {
          var virtualUser = AuthenticationManager.BuildVirtualUser(userName, true);

          var roles = Context.Domain.GetRoles();
          if (roles != null)
          {
            var groups = GetGroups(principal.Identity as ClaimsIdentity);
            foreach (var role in from role in roles
                                 let roleName = GetRoleName(role.Name)
                                 where groups.Contains(roleName.ToLower()) && !virtualUser.Roles.Contains(role)
                                 select role)
            {
              virtualUser.Roles.Add(role);
            }
            foreach (
                var role2 in
                    virtualUser.Roles.SelectMany(
                        role1 =>
                            RolesInRolesManager.GetRolesForRole(role1, true)
                                .Where(role2 => !virtualUser.Roles.Contains(role2))))
            {
              virtualUser.Roles.Add(role2);
            }

            // Setting the user to be an admin.
            //TODO = case sensitive
            virtualUser.RuntimeSettings.IsAdministrator =
                groups.Contains(Settings.GetSetting("ADFS.Authenticator.AdminUserRole", "Sitecore Local Administrators"), StringComparer.OrdinalIgnoreCase);

            if (virtualUser.RuntimeSettings.IsAdministrator)
              allowLoginToShell = true;
          }
          virtualUser.Profile.Email = "aap@app.com";
          Log.Debug("SitecoreOwin: Logging in virtual user: " + virtualUser.Name);
          AuthenticationManager.Login(virtualUser);
          var tracker = Tracker.Current;
          if (tracker != null)
            tracker.Session.Identify(virtualUser.Identity.Name);
        }
        #endregion
      }
      catch (ArgumentException ex)
      {
        Log.Error("ADFS::Login Failed!", ex, this);
      }
    }

    /// <summary>
    /// Gets the group names.
    /// </summary>
    /// <param name="claimsIdentity">The claims identity.</param>
    /// <returns></returns>
    private static IEnumerable<string> GetGroups(ClaimsIdentity claimsIdentity)
    {
      var enumerable =
          claimsIdentity.Claims.Where(
              c => c.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/role").ToList();
      var list = new List<string>();
      foreach (
          var str in
              enumerable.Select(claim => claim.Value.ToLower().Replace('-', '_'))
                  .Where(str => !list.Contains(str)))
      {
        list.Add(str);
      }
      return list.ToArray();
    }

    /// <summary>
    /// Gets the name of the role.
    /// </summary>
    /// <param name="roleName">Name of the role.</param>
    /// <returns></returns>
    private static string GetRoleName(string roleName)
    {
      if (!roleName.Contains('\\'))
        return roleName;
      return roleName.Split(new[]
      {
                '\\'
            })[1];
    }

    /// <summary>
    /// Writes the claims information.
    /// </summary>
    /// <param name="claimsIdentity">The claims identity.</param>
    private void WriteClaimsInfo(ClaimsIdentity claimsIdentity)
    {
      Log.Debug("Writing Claims Info", this);
      foreach (var claim in claimsIdentity.Claims)
        Log.Debug(string.Format("Claim : {0} , {1}", claim.Type, claim.Value), this);
    }


    /// <summary>
    /// Returns the LiU-id from the claims
    /// </summary>
    /// <param name="claimsIdentity">The claims identity.</param>
    public string GetLiUIdFromClaims(ClaimsIdentity claimsIdentity)
    {
      if (claimsIdentity == null)
      {
        Log.Error("Fick inga claims", this);
        return "";
      }

      if (claimsIdentity.Claims.All(c => c.Type != claimsIdentity.NameClaimType))
      {
        Log.Error("Fick inga Name claims", this);
        return "";
      }

      var enumerable = claimsIdentity.Claims.Where(
          c => c.Type == claimsIdentity.NameClaimType).ToList();
      foreach (var claim in enumerable)
        Log.Debug("Name claims to get LiU-ID from: " + claim.Value);
      var foundLiUId = enumerable.Find(d => d.Value.Contains(@"\")).Value;
      Log.Debug("Found liu id " + foundLiUId);
      var formattedLiuId = foundLiUId.Split(new Char[] { '\\' })[1];
      Log.Debug("Formatted liu id " + formattedLiuId);

      if (!string.IsNullOrEmpty(formattedLiuId))
        return formattedLiuId;
      return "";
    }


    public static void AddOrUpdateSessionCookie(string name, string value)
    {
      Assert.ArgumentNotNull(name, "name");
      Assert.ArgumentNotNull(value, "value");

      var cookies = HttpContext.Current.Request.Cookies;
      if (cookies[name] != null)
      {
        cookies[name].Value = value;
        cookies[name].Expires = DateTime.Now.AddDays(1);
      }
      else
      {
        var aCookie = new HttpCookie(name)
        {
          Value = value,
          Path = "/",
          Expires = DateTime.Now.AddMonths(3)
        };
        HttpContext.Current.Response.Cookies.Add(aCookie);
      }
    }

  }
}
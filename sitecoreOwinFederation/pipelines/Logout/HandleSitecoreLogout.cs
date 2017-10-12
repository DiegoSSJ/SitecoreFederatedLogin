using Sitecore.Diagnostics;
using Sitecore.Pipelines;
using Sitecore.Pipelines.Logout;
using Sitecore.Web.Authentication;
using System.Security.Claims;
using System.Web;

namespace SitecoreOwinFederatorLiU.pipelines.Logout
{
  public class HandleSitecoreLogout : PipelineArgs
  {
    /// <summary>Runs the processor to log out from Sitecore Owin when running sitecores logout pipeline</summary>
    public void Process(LogoutArgs args)
    {
      Log.Debug("SitecoreOwin: in HandleSitecoreLogout");
      args.RedirectUrl.Parameters.Add(Constants.LogoutFromSitecorePipelineParameterName, "true");
      //Log.Debug("SitecoreOwin: in HandleSitecoreLogout");
      //var thiss = this;
      //var user = Sitecore.Context.User;
      //var owinContext = HttpContext.Current.GetOwinContext();
      //var owinContextRequest = HttpContext.Current.Request.GetOwinContext();
      //var logonUserIdentity = HttpContext.Current.Request.LogonUserIdentity;
      //var requestContextUser = HttpContext.Current.Request.RequestContext.HttpContext.User;
      //string currentTicketId = TicketManager.GetCurrentTicketId();
      //var ticketIds = TicketManager.GetTicketIDs();
      //foreach (var ticketId in ticketIds)
      //{
      //  var thisTicket = TicketManager.GetTicket(ticketId);
      //  Log.Debug("SitecoreOwin: ind HandleSitecoreLogout this ticket has username: " + thisTicket?.UserName);
      //}
      //var ticket = TicketManager.GetTicket(currentTicketId, true);
      //var ticketUser = ticket?.UserName;
      //var activeUser = Sitecore.Security.Authentication.AuthenticationManager.GetActiveUser();
      //var accountUser = Sitecore.Security.Accounts.User.Current;
      //var userFromClaims = ClaimsPrincipal.Current;
      //var userFromMembership = System.Web.Security.Membership.GetUser();
      //Log.Debug("SitecoreOwin: in HandleSitecoreLogout Request user: " + requestContextUser.Identity.Name);
      //Log.Debug("SitecoreOwin: in HandleSitecoreLogout Claims user: " + userFromClaims?.Identity.Name);
      //Log.Debug("SitecoreOwin: in HandleSitecoreLogout Owin Context user: " + HttpContext.Current.GetOwinContext().Authentication.User.Identity.Name);
      //Log.Debug("SitecoreOwin: in HandleSitecoreLogout user from ticket: " + ticketUser);
      //if (HttpContext.Current.GetOwinContext() != null && HttpContext.Current.GetOwinContext().Authentication != null &&
      //  HttpContext.Current.GetOwinContext().Authentication.User != null && !Sitecore.Context.User.Domain.Equals("sitecore"))
      //{
      //  Log.Debug("SitecoreOwin: in HandleSitecoreLogout, user is logged in via Owin, logging out user");
      //  //HttpContext.Current.GetOwinContext().Authentication.SignOut();
      //}
      return;
    }

  }
}
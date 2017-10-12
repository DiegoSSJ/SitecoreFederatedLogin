namespace SitecoreOwinFederatorLiU
{
  public class Constants
  {
    public const string AdfsCurrentPathSaveCookieName = "adfsSavePath";
    public const string SitecoreUserTicketCookieName = "sitecore_userticket";
    public const string RedirectToCurrentLocationSettingName = "ADFS.Authenticator.RedirectToCurrentLocation";
    public const string RolesToRedirectToEditSettingName = "ADFS.Authenticator.RolesToRedirectToEdit";
    public const string UseParameterEditMode = "ADFS.Authenticator.UseParameterEditMode";
    public const string SitecoreStartEditingParameter = "?sc_mode=edit";
    public const string LogoutFromSitecoreParameterName = "fromSitecoreLogout";
    public const string LogoutFromSitecorePipelineParameterName = "fromSitecoreLogoutPipeline";
    public const string SitecoreReturnUrlParameterName = "returnUrl";
    public const string LogoutTransferParameterName = "transfer";
    public const string LogoutPath = "/logout";
    public const string LogoutTransferPath = LogoutPath + "?" + LogoutTransferParameterName + "=true" + "&" + SitecoreReturnUrlParameterName + "=";
    public const string LogoutFromSitecorePath = LogoutPath + "?" + LogoutFromSitecoreParameterName + "=true";
    public const string LogoutFromSitecorePipelinePath = LogoutPath + "?" + LogoutFromSitecorePipelineParameterName + "=true";
    public const string LogoutFromSitecoreAndSitecorePipelinePath = LogoutFromSitecorePath + "&" + LogoutFromSitecorePipelineParameterName + "=true";
    public const string DocumentLocationReloadHtml =
      "< !DOCTYPE html><html lang='sv-SE'><head> \n" +
          "<meta http-equiv='X-UA-Compatible' content='IE=edge' />\n" +
          "<meta name='viewport' content='width=device-width, initial-scale=1.0, user-scalable=1' />\n" +
           "<meta http-equiv='content-type' content='text/html;charset=UTF-8' />\n" +
           "<meta http-equiv='cache-control' content='no-cache,no-store' />\n" +
        "<meta http-equiv='pragma' content='no-cache' />\n" +
        "<meta http-equiv='expires' content='-1' />\n" +
        "<meta http-equiv='refresh' content='https://sc2-feat-cm.test.ad.liu.se/en' \n" +
        "<meta name='mswebdialog-title' content='Redirecting to Sitecore'/>\n" +
        "<title>Redirecting</title>\n" +
        "<script type='text/javascript'>\n" +
"//<![CDATA[\n" +
"window.onload = function() { console.log('Current location1: ' + window.location); \n" +
      "window.location = 'https://sc2-feat-cm.test.ad.liu.se/en'; \n" +
      "console.log('Current location2: ' + window.location);\n" +
      "window.location.replace('https://sc2-feat-cm.test.ad.liu.se/en');\n" +
      "console.log('Current location3: ' + window.location);\n" +
      "window.location.href = 'https://sc2-feat-cm.test.ad.liu.se/en';\n" +
      "console.log('Current location4: ' + window.location);\n" +
      "//window.location.reload() \n" +
      "}\n" +
        "//]]>\n" +
      "</script>\n" +
      "</head>\n<body></body>\n</html>";
  }
}
using System.Web;
using Sitecore.Diagnostics;
using Sitecore.Pipelines.PreprocessRequest;

namespace SitecoreOwinFederatorLiUNoDFS.pipelines.PreprocessRequest
{
  public class SuppressAdfsFormValidation : PreprocessRequestProcessor
  {
    public override void Process(PreprocessRequestArgs args)
    {
      Assert.ArgumentNotNull(args, "args");
      try
      {
        new SuppressFormValidation().Process(args);
      }
      catch (HttpRequestValidationException exception)
      {
        Log.Debug("SitecoreOwin: " + exception.Message);        
        string rawUrl = args.Context.Request.RawUrl;
        if (!rawUrl.Contains("sample item") && !rawUrl.Contains("secure") && !rawUrl.Contains("login") && !rawUrl.Equals("/") )
        {
          Log.Debug("SitecoreOwin:  re-throwing form validation error for path: " + rawUrl);
          throw;
        }
        Log.Debug("SitecoreOwin:  ignoring form validation error for path: " + rawUrl);
      }
    }
  }
}
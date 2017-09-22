using System.Collections.Generic;
using System.Security.Claims;

namespace SitecoreOwinFederatorLiUNoDFS.Models
{
    /// <summary>
    /// claims model to displau in rendering. Can be removed for production
    /// </summary>
    public class UserClaimsModel
    {
        public IEnumerable<Claim> Claims { get; set; }
    }    
}
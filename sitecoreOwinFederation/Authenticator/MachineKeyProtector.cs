using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.DataProtection;

namespace SitecoreOwinFederatorLiU.Authenticator
{
    /// <summary>
    /// MachineKey Protector, same implementation as internal machinekey protector.
    /// </summary>
    public class MachineKeyProtector : IDataProtector
    {
        private readonly string[] _purpose =
        {
         typeof(CookieAuthenticationMiddleware).FullName,
            CookieAuthenticationDefaults.AuthenticationType,
            "v1"
        };

        public byte[] Protect(byte[] userData)
        {
            return System.Web.Security.MachineKey.Protect(userData, _purpose);
        }

        public byte[] Unprotect(byte[] protectedData)
        {
            return System.Web.Security.MachineKey.Unprotect(protectedData, _purpose);
        }
    }
}
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.DataHandler;
using System;
using System.ComponentModel.DataAnnotations;
using System.Data.Entity;
using System.Data.Entity.ModelConfiguration.Conventions;
using System.Data.SqlClient;
using System.Linq;
using System.Timers;
using System.Threading.Tasks;
using Sitecore.Diagnostics;
using System.Data.Entity.Infrastructure;

/// <summary>
/// This implementation is a literal copy paste from Vittorio Bertocci
/// original source: https://gist.github.com/vibronet/90d4646c273930ff12d4
/// </summary>
namespace SitecoreOwinFederator.Authenticator
{
  /// <summary>
  /// Model for use with the session authentication store. data will be stored into database
  /// </summary>
  public class AuthSessionEntry
  {
    [Key]
    public string Key { get; set; }
    public DateTimeOffset? ValidUntil { get; set; }
    public string TicketString { get; set; }
  }

  public class SQLAuthSessionStoreContext : DbContext
  {
    public SQLAuthSessionStoreContext(string init = "AuthSessionStoreContext")
        : base(init)
    { }
    public DbSet<AuthSessionEntry> Entries { get; set; }
    protected override void OnModelCreating(DbModelBuilder modelBuilder)
    {
      modelBuilder.Conventions.Remove<PluralizingTableNameConvention>();
    }
  }

  public class SqlAuthSessionStoreInitializer : DropCreateDatabaseIfModelChanges<SQLAuthSessionStoreContext>
  {
  }

  /// <summary>
  /// Session store to be used with the OWIN cookie authentication middleware
  /// </summary>
  public class SqlAuthSessionStore : IAuthenticationSessionStore
  {
    private string _connectionString;
    private TicketDataFormat _formatter;
    private static Timer _gcTimer;
    private static SQLAuthSessionStoreContext _permStore;
    public SqlAuthSessionStore(TicketDataFormat tdf, string cns = "AuthSessionStoreContext")
    {
      //Log.Info("SitecoreOwin: Initializing SqlAuthSessionStore", this);
      _connectionString = cns;
      _formatter = tdf;
      if (_gcTimer == null)
      {
        _gcTimer = new Timer(900000); // 15 min               
        _gcTimer.Elapsed += GarbageCollect;
        _gcTimer.Enabled = true;
      }
      if (_permStore == null)
        _permStore = new SQLAuthSessionStoreContext(_connectionString);
    }

    private void GarbageCollect(Object source, ElapsedEventArgs eea)
    {
      DateTimeOffset now = DateTimeOffset.Now.ToUniversalTime();
      int gcTries = 0;
      bool collected = false;

      //Log.Info("ADFS: In GarbageCollect", this);
      //Log.Info("ADFS: GarbageCollect call trace: " + Environment.StackTrace, this);

      if (_permStore?.Entries == null)
      {
        Log.SingleError("SitecoreOwin: In GarbageCollect, permStore or entries is null, GarbageCollect won't run!", this);
        return;
      }

      while (!collected && gcTries < 10)
      {
        gcTries++;
        try
        {            
          foreach (var entry in _permStore.Entries)
          {
            AuthenticationTicket unprotectedKey = _formatter.Unprotect(entry.TicketString);
            if (unprotectedKey == null)
            {
              // The key is unprotectable, delete it from db
              Log.Error("SitecoreOwin: In GarbageCollect, unprotected key is null for TicketString: " + entry.TicketString, this);
              Log.Error("SitecoreOwin: In GarbageCollect, removing entry from database: " + entry.Key, this);
              _permStore.Entries.Remove(entry);              
            }
            if (unprotectedKey != null && unprotectedKey.Properties?.ExpiresUtc == null)
              Log.Error("SitecoreOwin: In GarbageCollect, unprotected key properties or expires utc is null for ticketstring: " + entry.TicketString, this);            

            var expiresAt = unprotectedKey?.Properties?.ExpiresUtc;
            if (expiresAt < now)
            {
              _permStore.Entries.Remove(entry);
            }
          }

          try
          {
            _permStore.SaveChanges();
            collected = true;
          }
          catch (DbUpdateConcurrencyException ex)
          {
            // Update the values of the entity that failed to save from the store 
            LogErrorToSitecore(
            "Update Concurrency Exception in Garbage Collect", ex);
            ex.Entries.Single().Reload();   
          }
        }
        // Handle wrongly configured database strings and other situations like that. 
        catch (SqlException sqlException)
        {
          LogErrorToSitecore(
             " sql Exception doing garbage collect for EFAuthStore, is the database for the auth tokens well configured ?", sqlException);
        }
        catch (Exception e)
        {
          LogErrorToSitecore("Exception in garbage collect", e);
        }
      }
      if (!collected)
        Log.Error("SitecoreOwin: collection of auth keys not done after " + gcTries + " tries ", this);
    }

    public Task<string> StoreAsync(AuthenticationTicket ticket)
    {
      //Log.Info("SitecoreOwin: In StoreAsync", this);
      string key = Guid.NewGuid().ToString();
      AuthSessionEntry newEntry = new AuthSessionEntry
      {
        Key = key,
        TicketString = _formatter.Protect(ticket),
        ValidUntil = ticket.Properties.ExpiresUtc
      };
      try
      {
        _permStore.Entries.Add(newEntry);
        _permStore.SaveChanges();
      }
      catch (Exception e)
      {
        LogErrorToSitecore("Error creating session key in authentication key database", e);
        try
        {
          _permStore.Entries.Remove(newEntry);
        }
        catch (Exception e2)
        {
          LogErrorToSitecore("Error removing session key after error creating it", e2);
        }
        // We want Owin to ignore that the key was added if it didn't work, is this the way to do it?
        // ->gives an error, but the site continues to work.okay?
      key = null;
      }
      return Task.FromResult(key);
    }

    public Task RenewAsync(string key, AuthenticationTicket ticket)
    {
      //Log.Info("SitecoreOwin: In RenewAsync", this)
      AuthSessionEntry myEntry = _permStore.Entries.Find(key);
      if (myEntry != null)
      {
        myEntry.TicketString = _formatter.Protect(ticket);
      }
      else
      {
        AuthSessionEntry newEntry = new AuthSessionEntry
        {
          Key = key,
          TicketString = _formatter.Protect(ticket)          
        };
        try
        {
          _permStore.Entries.Add(newEntry);
        }
        catch (Exception e)
        {
          LogErrorToSitecore("Error renewing session key in authentication key database with new key ", e);
          try
          {
            _permStore.Entries.Remove(newEntry);
          }
          catch (Exception e2)
          {
            LogErrorToSitecore("Error removing session key after error creating it", e2);
          }
          // We want Owin to ignore that the key was added if it didn't work, is this the way to do it?
          // ->gives an error, but the site continues to work.okay?
          key = null;
        }
      }
      _permStore.SaveChanges();
      return Task.FromResult(0);
    }

    public Task<AuthenticationTicket> RetrieveAsync(string key)
    {
      //Log.Info("SitecoreOwin: In RetrieveAsync", this);
      //Log.Info("SitecoreOwin: RetrieveAsync call trace: " + Environment.StackTrace, this);
      AuthenticationTicket ticket = null;
      AuthSessionEntry myEntry = _permStore.Entries.Find(key);  
      if (myEntry != null)
        ticket = _formatter.Unprotect(myEntry.TicketString);
      return Task.FromResult(ticket);
    }

    public Task RemoveAsync(string key)
    {
      //Log.Info("SitecoreOwin: In RemoveAsync", this);   
      AuthSessionEntry myEntry = _permStore.Entries.Find(key);
      if (myEntry != null)
      {
        _permStore.Entries.Remove(myEntry);
        _permStore.SaveChanges();
      }
      return Task.FromResult(0);
    }

    private static string GetExceptionMessages(Exception e, string msgs = "")
    {
      if (e == null) return string.Empty;
      if (msgs == "") msgs = e.Message;
      if (e.InnerException != null)
        msgs += "\r\nInnerException: " + GetExceptionMessages(e.InnerException);
      return msgs;
    }

    private static string GetExceptionStackTraces(Exception e, string msgs = "")
    {
      if (e == null) return string.Empty;
      if (msgs == "") msgs = e.StackTrace;
      if (e.InnerException != null)
        msgs += "\r\nStackTrace: " + GetExceptionStackTraces(e.InnerException);
      return msgs;
    }

    private void LogErrorToSitecore(string mainText, Exception e)
    {
      Log.SingleError(
        "SitecoreOwin: " + mainText  + ". Exception: " +
        e.Message, this);
      if (e.InnerException != null)
      {
        Log.SingleError("SitecoreOwin: Inner Messages " + GetExceptionMessages(e), this);
        Log.SingleError("SitecoreOwin: Inner StackTrace " + GetExceptionStackTraces(e), this);
      }
    }
  }


}
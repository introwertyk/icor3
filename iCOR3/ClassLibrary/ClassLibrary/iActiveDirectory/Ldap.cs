using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices.Protocols;
using System.Net;

using iCOR3.iSecurityComponent;

namespace iCOR3.iActiveDirectory
{
	/// <summary>
	/// Basic Ldap methods class. Custom LDAP (S.DS.P) libraries implementation.
	/// Supports asynchronous directory data retrieval.  
	/// </summary>
	public class Ldap : IDisposable
	{
		#region Constants
		private const int CONN_TIME_OUT = 600; //seconds
		#endregion

		#region Variables
		private bool bDisposed;
		private string _baseSearchDn;
		private string[] _domainControllers;
		private Int32 _port;
		private Int32 _pageSize;
		private Int32 _protocolVersion;
		private System.DirectoryServices.Protocols.SearchScope _searchScope;
		private Credentials _secureCredentials;
		private AuthType _authenticationType;

		#endregion

		#region Properties
		/// <summary>
		/// Base search DistinguishedName
		/// </summary>
		public string BaseSearchDn
		{
			get
			{
				return this._baseSearchDn;
			}
			set
			{
				this._baseSearchDn = value;
			}
		}
		
		/// <summary>
		/// LDAP providers collection
		/// </summary>
		public string[] DomainControllers
		{
			get
			{
				return this._domainControllers;
			}
			set
			{
				this._domainControllers = value;
			}
		}

		/// <summary>
		/// LDAP TCP port
		/// </summary>
		public Int32 Port
		{
			get
			{
				return this._port;
			}
			set
			{
				this._port = value;
			}
		}
	
		/// <summary>
		/// Allowed PageSize; 0 - not supported
		/// </summary>
		public Int32 PageSize
		{
			get
			{
				return this._pageSize;
			}
			set
			{
				this._pageSize = value;
			}
		}

		/// <summary>
		/// LDAP Protocol Version; 2.0 default
		/// </summary>
		public Int32 ProtocolVersion
		{
			get
			{
				return this._protocolVersion;
			}
			set
			{
				this._protocolVersion = value;
			}
		}

		/// <summary>
		/// Directory Search Scope
		/// </summary>
		public System.DirectoryServices.Protocols.SearchScope SearchScope
		{
			get
			{
				return this._searchScope;
			}
			set
			{
				this._searchScope = value;
			}
		}

		/// <summary>
		/// Secure LDAP connection credentials
		/// </summary>
		public Credentials SecureCredentials
		{
			get
			{
				return this._secureCredentials;
			}
			set
			{
				this._secureCredentials = value;
			}
		}
		#endregion

		#region Constructors
		public Ldap(string ServerFQDN, Credentials oSecureCredentials, string BaseDn, Int32 Port, AuthType AuthenticationType)
		{
			try
			{
				this.bDisposed = false;

				this.PageSize = 500;
				this.ProtocolVersion = 3;
				this.SecureCredentials = oSecureCredentials;

				this.Port = Port;
				this.BaseSearchDn = BaseDn;
				this._authenticationType = AuthenticationType;

				this.DomainControllers = new string[] { ServerFQDN };
			}
			catch (Exception eX)
			{
				throw new Exception(string.Format("{0}::{1}", new StackFrame(0, true).GetMethod().Name, eX.Message));
			}
		}
		public Ldap(string ServerFQDN, string UserName, string Password) : this(ServerFQDN, new Credentials(Password, UserName), null, 389, AuthType.Basic) { }
		public Ldap(string ServerFQDN, string UserName, string Password, AuthType AuthenticationType) : this(ServerFQDN, new Credentials(Password, UserName), null, 389, AuthenticationType) { }
		public Ldap(string ServerFQDN, string UserName, string Password, string BaseDn, Int32 Port) : this(ServerFQDN, new Credentials(Password, UserName), BaseDn, Port, AuthType.Basic) { }
		public Ldap(string ServerFQDN, string UserName, string Password, string BaseDn, Int32 Port, AuthType AuthenticationType) : this(ServerFQDN, new Credentials(Password, UserName), BaseDn, Port, AuthenticationType) { }
		#endregion

		#region Public Instance Methods
		/// <summary>
		/// Asynchronously retrieves MS AD(DS) objects and casts attributes into dictionaries of key/value pairs. Where key represents AD attribute name and value (object) corresponds to attribute value.
		/// </summary>
		public IEnumerable<SortedList<string, object>> RetrieveAttributes(string LdapFilter, string[] AttributesToLoad, bool ShowDeleted)
		{
			using (LdapConnection ldapConnection = this.OpenLdapConnection(this.DomainControllers[0], this.SecureCredentials))
			{
				SearchResponse dirRes = null;
				SearchRequest srRequest = null;
				PageResultRequestControl rcPageRequest = null;
				PageResultResponseControl rcPageResponse = null;

				string sServerName = ldapConnection.SessionOptions.HostName;
				string sBaseDn = (this.BaseSearchDn == null)
					? String.Format("DC={0}", sServerName.Substring(sServerName.IndexOf('.') + 1).Replace(".", ",DC="))
					: this.BaseSearchDn;

				srRequest = new SearchRequest(
							sBaseDn,
							LdapFilter,
							this.SearchScope,
							AttributesToLoad
							);

				if (ShowDeleted)
				{
					srRequest.Controls.Add(new ShowDeletedControl());
				}
				//PAGED
				if (this.PageSize > 0)
				{
					bool bHasCookies = false;
					rcPageRequest = new PageResultRequestControl();
					rcPageRequest.PageSize = this.PageSize;

					srRequest.Controls.Add(rcPageRequest);

					do
					{
						try
						{
							dirRes = (SearchResponse)ldapConnection.SendRequest(srRequest);
							DirectoryControl[] dirControls = dirRes.Controls;

							rcPageResponse = (dirControls.Rank > 0 && dirControls.GetLength(0) > 0) ? (PageResultResponseControl)dirRes.Controls.GetValue(0) : (PageResultResponseControl)null;
						}
						catch (Exception eX)
						{
							throw new Exception(string.Format("{0}::{1}", new StackFrame(0, true).GetMethod().Name, eX.Message));
						}

						if (dirRes.Entries.Count > 1)
						{
							foreach (SearchResultEntry srEntry in dirRes.Entries)
							{
								SortedList<string, object> dicProperties = new SortedList<string, object>(StringComparer.OrdinalIgnoreCase);
								foreach (string sAttribute in AttributesToLoad)
								{
									if (srEntry.Attributes.Contains(sAttribute))
									{
										dicProperties.Add(sAttribute, srEntry.Attributes[sAttribute].GetValues(srEntry.Attributes[sAttribute][0].GetType()));
									}
								}
								yield return dicProperties;
							}


							if (rcPageResponse != null && rcPageResponse.Cookie.Length > 0)
							{
								rcPageRequest.Cookie = rcPageResponse.Cookie;
								bHasCookies = true;
							}
							else
							{
								bHasCookies = false;
							}
						}
						else
						{
							foreach (SearchResultEntry srEntry in dirRes.Entries)
							{
								SortedList<string, object> dicProperties = new SortedList<string, object>(StringComparer.OrdinalIgnoreCase);
								foreach (string sAttribute in AttributesToLoad)
								{
									if (srEntry.Attributes.Contains(sAttribute))
									{
										dicProperties.Add(sAttribute, srEntry.Attributes[sAttribute].GetValues(srEntry.Attributes[sAttribute][0].GetType()));
									}
								}
								yield return dicProperties;
								bHasCookies = false;
							}
						}
					}
					while (bHasCookies);
				}
				//NOT PAGED
				else
				{
					try
					{
						dirRes = (SearchResponse)ldapConnection.SendRequest(srRequest);
					}
					catch (Exception eX)
					{
						throw new Exception(string.Format("{0}::{1}", new StackFrame(0, true).GetMethod().Name, eX.Message));
					}

					if (dirRes.Entries.Count > 0)
					{
						foreach (SearchResultEntry srEntry in dirRes.Entries)
						{
							SortedList<string, object> dicProperties = new SortedList<string, object>(StringComparer.OrdinalIgnoreCase);
							foreach (string sAttribute in AttributesToLoad)
							{
								if (srEntry.Attributes.Contains(sAttribute))
								{
									dicProperties.Add(sAttribute, srEntry.Attributes[sAttribute].GetValues(srEntry.Attributes[sAttribute][0].GetType()));
								}
							}
							yield return dicProperties;
						}
					}
				}

				//dispose
				if (dirRes != null) { dirRes = null; }
				if (srRequest != null) { srRequest = null; }
				if (rcPageRequest != null) { rcPageRequest = null; }
				if (rcPageResponse != null) { rcPageResponse = null; }
			}
		}

		/// <summary>
		/// Opens new LDAP connection with end-server.
		/// </summary>
		public LdapConnection OpenLdapConnection(string sServerName, Credentials secureCredentials)
		{
			try
			{
				LdapDirectoryIdentifier oLdapDirectory = new LdapDirectoryIdentifier(sServerName, this.Port);

				LdapConnection ldapConnection = new LdapConnection(oLdapDirectory, new NetworkCredential(secureCredentials.UserName, secureCredentials.Password), this._authenticationType);
				ldapConnection.Bind();
				ldapConnection.Timeout = TimeSpan.FromSeconds(CONN_TIME_OUT);
				ldapConnection.SessionOptions.TcpKeepAlive = true;
				ldapConnection.SessionOptions.ProtocolVersion = this.ProtocolVersion;

				ldapConnection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
				ldapConnection.AutoBind = false;

				return ldapConnection;
			}
			catch (Exception eX)
			{
				throw new Exception(string.Format("{0}::{1}", new StackFrame(0, true).GetMethod().Name, eX.Message));
			}
		}

		/// <summary>
		/// Opens new LDAP connection with end-server.
		/// </summary>
		public LdapConnection OpenLdapConnection()
		{
			try
			{
				return this.OpenLdapConnection(this.DomainControllers[0], this.SecureCredentials);
			}
			catch (Exception eX)
			{
				throw new Exception(string.Format("{0}::{1}", new StackFrame(0, true).GetMethod().Name, eX.Message));
			}
		}
		#endregion

		#region IDisposable Members
		public void Dispose()
		{
			Dispose(true);
			GC.SuppressFinalize(this);
		}

		protected virtual void Dispose(bool bDisposing)
		{
			if (!this.bDisposed)
			{
				if (bDisposing)
				{
				}

				this.bDisposed = true;
			}
		}

		#endregion
	}
}

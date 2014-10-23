using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Reflection;
using System.Text;


namespace SecureComponent.Crypto
{
	public class CryptoClass : IDisposable
	{
		#region Constructors
		CryptoClass()
		{ }
		#endregion

		#region Static Methods
		/// <summary>
		/// Function Encrypts password using PKI certificate and RSA algorithm
		/// </summary>
		/// <param name="certificatePath">Certificate path is the SubjectName of the PKI certificate (DistinguishedName)</param>
		/// <param name="storeName">Local store name</param>
		/// <param name="storeLocation">Local store location</param>
		/// <param name="plainPassword">Plain text format password to encrypt</param>
		/// <returns></returns>
		public static byte[] Encrypt(string certificatePath, string storeName, string storeLocation, string plainPassword)
		{
			byte[] encryptedPassword;

			X509Store xStore;
			if (storeLocation.Equals("CurrentUser", StringComparison.OrdinalIgnoreCase))
			{
				xStore = new X509Store(storeName, StoreLocation.CurrentUser);
			}
			else if (storeLocation.Equals("LocalMachine", StringComparison.OrdinalIgnoreCase))
			{
				xStore = new X509Store(storeName, StoreLocation.LocalMachine);
			}
			else
			{
				throw new Exception(string.Format("{0}::{1}", new StackFrame(0, true).GetMethod().Name, "Failed to locate the store location"));
			}
			xStore.Open(OpenFlags.ReadOnly);

			try
			{
				X509Certificate2 certificate = xStore.Certificates.OfType<X509Certificate2>().FirstOrDefault(xCert => xCert.Subject.Equals(certificatePath, StringComparison.OrdinalIgnoreCase));
				using (System.Security.Cryptography.RSACryptoServiceProvider cryptoRSA = new RSACryptoServiceProvider())
				{
					cryptoRSA.FromXmlString(certificate.PublicKey.Key.ToXmlString(false));

					encryptedPassword = cryptoRSA.Encrypt(System.Text.Encoding.UTF8.GetBytes(plainPassword), false);
				}
			}
			catch (Exception eX)
			{
				throw new Exception(string.Format("{0}::{1}", new StackFrame(0, true).GetMethod().Name, eX.Message));
			}
			finally
			{
				xStore.Close();
			}
			return encryptedPassword;
		}

		/// <summary>
		/// Function Decrypts password using PKI certificate and RSA algorithm
		/// </summary>
		/// <param name="certificatePath">Certificate path is the SubjectName of the PKI certificate (DistinguishedName)</param>
		/// <param name="storeName">Local store name</param>
		/// <param name="storeLocation">Local store location</param>
		/// <param name="encryptedPassword">Encrypted password to decrypt</param>
		public static string Decrypt(string certificatePath, string storeName, string storeLocation, byte[] encryptedPassword)
		{
			string decryptedPassword = null;
			X509Store xStore;
			if (storeLocation.Equals("CurrentUser", StringComparison.OrdinalIgnoreCase))
			{
				xStore = new X509Store(storeName, StoreLocation.CurrentUser);
			}
			else if (storeLocation.Equals("LocalMachine", StringComparison.OrdinalIgnoreCase))
			{
				xStore = new X509Store(storeName, StoreLocation.LocalMachine);
			}
			else
			{
				throw new Exception(string.Format("{0}::{1}", new StackFrame(0, true).GetMethod().Name, "Failed to locate the store location"));
			}
			xStore.Open(OpenFlags.ReadOnly);

			try
			{
				X509Certificate2 certificate = xStore.Certificates.OfType<X509Certificate2>().FirstOrDefault(xCert => xCert.Subject.Equals(certificatePath, StringComparison.OrdinalIgnoreCase));
				using (System.Security.Cryptography.RSACryptoServiceProvider cryptoRSA = new RSACryptoServiceProvider())
				{
					string privateMagic = certificate.PrivateKey.ToXmlString(true);
					cryptoRSA.FromXmlString(privateMagic);

					char[] decrypted = cryptoRSA.Decrypt(encryptedPassword, false).Select(b => (char)b).ToArray();

					decryptedPassword = new string(decrypted);
				}
			}
			catch (Exception eX)
			{
				throw new Exception(string.Format("{0}::{1}", new StackFrame(0, true).GetMethod().Name, eX.Message));
			}
			finally
			{
				xStore.Close();
			}
			return decryptedPassword;
		}

		/// <summary>
		/// Function Decrypts password using PKI certificate and RSA algorithm
		/// </summary>
		/// <param name="certificatePath">Certificate path is the SubjectName of the PKI certificate (DistinguishedName)</param>
		/// <param name="storeName">Local store name</param>
		/// <param name="storeLocation">Local store location</param>
		/// <param name="encryptedPassword">Encrypted password to decrypt in Base64 format</param>
		public static string Decrypt(string certificatePath, string storeName, string storeLocation, string encryptedPassword)
		{
			return Decrypt(certificatePath, storeName, storeLocation, Convert.FromBase64String(encryptedPassword));
		}
		#endregion

		#region IDisposable Members

		public void Dispose()
		{
			try
			{
			}
			catch (Exception eX)
			{
				throw new Exception(string.Format("{0}::{1}", new StackFrame(0, true).GetMethod().Name, eX.Message));
			}
		}
		#endregion
	}
}

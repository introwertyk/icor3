﻿using System;
using System.Diagnostics;
using System.Linq;
using System.Security;

namespace iCOR3.iSecurityComponent
{
	/// <summary>
	/// Simple encryping class. Encrypted credentials with this class are not considered to be secure.
	/// XORFF Encryption (ISSpyra)
	/// </summary>
	public class SimpleCrypto : IDisposable
	{
		#region Private Variables
		private bool bDisposed;
		#endregion

		#region Constructors
		public SimpleCrypto()
		{
			this.bDisposed = false;
		}
		#endregion

		#region Public Methods
		/// <summary>
		/// Encrypts text into base64 format string. Binary value of each text character is simply chagned with binary negation.
		/// </summary>
		public string Encrypt(string PlainText)
		{
			try
			{
				return Convert.ToBase64String(PlainText.ToCharArray().Select(cChar => (byte)(~Convert.ToByte(cChar))).ToArray());
			}
			catch (Exception ex)
			{
				throw new Exception(string.Format("{0}::{1}", new StackFrame(0, true).GetMethod().Name, ex.Message));
			}
		}

		/// <summary>
		/// Decrypts text from base64 format string. Binary value of each text character is simply chagned with binary negation.
		/// </summary>
		public string Decrypt(string DecryptedText)
		{
			try
			{
				return new String(Convert.FromBase64String(DecryptedText).Select(bByte => Convert.ToChar((byte)~bByte)).ToArray());
			}
			catch (Exception ex)
			{
				throw new Exception(string.Format("{0}::{1}", new StackFrame(0, true).GetMethod().Name, ex.Message));
			}
		}
		#endregion

		#region Public Methods
		/// <summary>
		/// Encrypts text into base64 format string. Binary value of each text character is simply chagned with binary negation.
		/// </summary>
		public static string EncryptString(string PlainText)
		{
			try
			{
				return Convert.ToBase64String(PlainText.ToCharArray().Select(cChar => (byte)(~Convert.ToByte(cChar))).ToArray());
			}
			catch (Exception ex)
			{
				throw new Exception(string.Format("{0}::{1}", new StackFrame(0, true).GetMethod().Name, ex.Message));
			}
		}

		/// <summary>
		/// Decrypts text from base64 format string. Binary value of each text character is simply chagned with binary negation.
		/// </summary>
		public static string DecryptString(string EncryptedText)
		{
			try
			{
				return new String(Convert.FromBase64String(EncryptedText).Select(bByte => Convert.ToChar((byte)~bByte)).ToArray());
			}
			catch (Exception ex)
			{
				throw new Exception(string.Format("{0}::{1}", new StackFrame(0, true).GetMethod().Name, ex.Message));
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

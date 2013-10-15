using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace iCOR3.iSecurityComponent
{
	/// <summary>
	/// Class defining core encryption functionality.
	/// Entry point for different encryption libraries used.
	/// </summary>
	public class Encryption
	{
		#region Static Methods
		public static string Decrypt(string EncryptedText)
		{
			try
			{
				if (EncryptedText.StartsWith("::SC::"))
				{
					return iSecurityComponent.SimpleCrypto.DecryptString(EncryptedText.Substring(6));
				}
				else
				{
					return EncryptedText;
				}
			}
			catch (Exception ex)
			{
				throw new Exception(string.Format("{0}::{1}", new StackFrame(0, true).GetMethod().Name, ex.Message));
			}
		}
		#endregion
	}
}

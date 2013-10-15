using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;

using iCOR3.iSecurityComponent;

namespace ToolBox
{
	class scrypto
	{
		static void Main(string[] args)
		{
			if (args.Length < 2)
			{
				Message();
			}
			else
			{
				try
				{
					if (args[0].Equals("/E", StringComparison.OrdinalIgnoreCase))
					{
						Console.WriteLine(iCOR3.iSecurityComponent.SimpleCrypto.EncryptString(args[1]));
					}
					else if (args[0].Equals("/D", StringComparison.OrdinalIgnoreCase))
					{
						Console.WriteLine(iCOR3.iSecurityComponent.SimpleCrypto.DecryptString(args[1]));
					}
					else
					{
						Message();
					}
				}
				catch (Exception eX)
				{
					Console.WriteLine("Error: Incorrect input string format!");
				}
			}
		}

		static void Message()
		{
			Console.WriteLine(String.Format(@"
Please use:
{0} [/E] [/D] ""plain text""
	/E	Encrypt to Base64 format
	/D	Decrypt from Base64 format
",
		   Path.GetFileName(Assembly.GetExecutingAssembly().CodeBase)
		   ));
		}
	}
}

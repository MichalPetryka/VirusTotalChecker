using System;

namespace VirusTotalChecker.Api
{
	public class VirusTotalException : Exception
	{
		internal VirusTotalException(string message) : base(message)
		{
		}
	}
}

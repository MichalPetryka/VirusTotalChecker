using System;

namespace VirusTotalChecker.Api
{
	public class RateLimitException : Exception
	{
		public string Resource { get; }

		public RateLimitException(string resource)
		{
			Resource = resource;
		}
	}
}
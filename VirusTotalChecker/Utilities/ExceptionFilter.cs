using System;

namespace VirusTotalChecker.Utilities
{
	public static class ExceptionFilter
	{
		public static volatile bool ShowStacktraces;
		public static string GetErrorMessage(Exception ex) => ShowStacktraces ? ex.ToString() : ex.Message;
	}
}

using System.ComponentModel;

namespace VirusTotalChecker.Configuration
{
	public class VirusTotalDebugConfig
	{
		[DefaultValue(false)]
		public bool ForceSdl { get; set; } = false;
		[DefaultValue(false)]
		public bool ShowStacktraces { get; set; } = false;
		[DefaultValue(false)]
		public bool LogExit { get; set; } = false;
	}
}

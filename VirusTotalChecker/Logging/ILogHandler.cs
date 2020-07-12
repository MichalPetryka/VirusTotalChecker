namespace VirusTotalChecker.Logging
{
	public interface ILogHandler
	{
		public void Log(string message, LogType logType = LogType.Info);
	}
}
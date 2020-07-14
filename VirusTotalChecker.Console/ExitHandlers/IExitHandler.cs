namespace VirusTotalChecker.Console.ExitHandlers
{
	interface IExitHandler
	{
		bool LogExit { get; set; }
		void Setup();
	}
}

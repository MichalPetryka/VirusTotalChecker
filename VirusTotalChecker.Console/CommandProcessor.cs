using System;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using VirusTotalChecker.Console.ExitHandlers;
using VirusTotalChecker.Utilities;

namespace VirusTotalChecker.Console
{
	public class CommandProcessor
	{
		private readonly DataProcessor _processor;

		public CommandProcessor(DataProcessor processor)
		{
			_processor = processor;
		}

		public void ProcessCommand(string[] command)
		{
			switch (command[0])
			{
				case "exit":
					{
						Program.Exit();
						return;
					}
				case "lockinput":
					{
						string line = ConsoleUtil.ReadLineLock();
						if (string.IsNullOrWhiteSpace(line))
						{
							ConsoleUtil.WriteLine("Cannot execute an empty command!", ConsoleColor.Yellow);
							break;
						}
						// ReSharper disable once TailRecursiveCall
						ProcessCommand(line.Split(" ", StringSplitOptions.RemoveEmptyEntries));
						return;
					}
				case "stacktraces":
					{
						if (ExceptionFilter.ShowStacktraces)
						{
							ExceptionFilter.ShowStacktraces = false;
							ConsoleUtil.WriteLine("Disabled stacktraces", ConsoleColor.Blue);
						}
						else
						{
							ExceptionFilter.ShowStacktraces = true;
							ConsoleUtil.WriteLine("Enabled stacktraces", ConsoleColor.Blue);
						}
						break;
					}
				case "logexit":
					{
						if (command.Length < 2)
						{
							ConsoleUtil.WriteLine("You need to specify exit logging state!", ConsoleColor.Yellow);
							break;
						}

						string state = command[1];
						if (string.IsNullOrWhiteSpace(state))
						{
							ConsoleUtil.WriteLine("Specified state is empty!", ConsoleColor.Yellow);
							break;
						}

						if (!bool.TryParse(state, out bool enabled))
						{
							ConsoleUtil.WriteLine($"{state} isn't a valid boolean!", ConsoleColor.Yellow);
							break;
						}

						foreach (IExitHandler handler in Program.ExitHandlers)
							handler.LogExit = enabled;
						break;
					}
				case "eicar":
					{
						const string eicar = "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F";
						_processor.ProcessFile(eicar, eicar);
						break;
					}
				case "scan":
					{
						if (command.Length < 2)
						{
							ConsoleUtil.WriteLine("You need to specify the desired file!", ConsoleColor.Yellow);
							break;
						}

						string cmd = command[1];
						if (string.IsNullOrWhiteSpace(cmd))
						{
							ConsoleUtil.WriteLine("Specified path is empty!", ConsoleColor.Yellow);
							break;
						}

						string path = Path.GetFullPath(cmd);
						if (!File.Exists(path))
						{
							ConsoleUtil.WriteLine($"File {path} does not exist!", ConsoleColor.Yellow);
							break;
						}

						_processor.ProcessFile(path);
						break;
					}
				case "scandirectory":
					{
						if (command.Length < 2)
						{
							ConsoleUtil.WriteLine("You need to specify the desired directory!",
								ConsoleColor.Yellow);
							break;
						}

						string cmd = command[1];
						if (string.IsNullOrWhiteSpace(cmd))
						{
							ConsoleUtil.WriteLine("Specified path is empty!", ConsoleColor.Yellow);
							break;
						}

						string path = Path.GetFullPath(cmd);
						if (!Directory.Exists(path))
						{
							ConsoleUtil.WriteLine($"Directory {path} does not exist!", ConsoleColor.Yellow);
							break;
						}

						string filter = "*";
						if (command.Length >= 3)
							filter = command[2];

						bool recursive = true;
						if (command.Length >= 4)
							recursive = bool.Parse(command[3]);

						_processor.ProcessDirectory(path, filter, recursive);
						break;
					}
				case "scanhash":
					{
						if (command.Length < 2)
						{
							ConsoleUtil.WriteLine("You need to specify a hash!", ConsoleColor.Yellow);
							break;
						}

						string hash = command[1];
						if (string.IsNullOrWhiteSpace(hash))
						{
							ConsoleUtil.WriteLine("Specified hash is empty!", ConsoleColor.Yellow);
							break;
						}

						_processor.ProcessFile(hash, hash);
						break;
					}
				case "scanprocesses":
					{
						string filter = ".*";
						if (command.Length >= 2)
							filter = command[1];

						Regex regex = new Regex(filter);

						bool scanSubmodules = false;
						if (command.Length >= 3)
							scanSubmodules = bool.Parse(command[2]);

						foreach (Process process in Process.GetProcesses())
							try
							{
								if (regex.IsMatch(process.ProcessName))
								{
									_processor.ProcessFile(process.MainModule!.FileName);
									if (scanSubmodules)
										foreach (ProcessModule module in process.Modules)
											_processor.ProcessFile(module.FileName);
								}
							}
							catch (Exception ex)
							{
								ConsoleUtil.WriteLine($"Failed to scan {process.ProcessName}. Error: {ExceptionFilter.GetErrorMessage(ex)}", ConsoleColor.Red);
							}
						break;
					}
				case "scanprocess":
					{
						if (command.Length < 2)
						{
							ConsoleUtil.WriteLine("You need to specify the desired process id!", ConsoleColor.Yellow);
							break;
						}

						string id = command[1];
						if (string.IsNullOrWhiteSpace(id))
						{
							ConsoleUtil.WriteLine("Specified id is empty!", ConsoleColor.Yellow);
							break;
						}

						if (!int.TryParse(id, out int pid))
						{
							ConsoleUtil.WriteLine("Specified id isn't a valid number!", ConsoleColor.Yellow);
							break;
						}

						bool scanSubmodules = false;
						if (command.Length >= 3)
							scanSubmodules = bool.Parse(command[2]);

						Process process = Process.GetProcessById(pid);
						_processor.ProcessFile(process.MainModule!.FileName);
						if (scanSubmodules)
							foreach (ProcessModule module in process.Modules)
								_processor.ProcessFile(module.FileName);
						break;
					}
				case "scanfilelink":
					{
						if (command.Length < 2)
						{
							ConsoleUtil.WriteLine("You need to specify the desired link!", ConsoleColor.Yellow);
							break;
						}

						string link = command[1];
						if (string.IsNullOrWhiteSpace(link))
						{
							ConsoleUtil.WriteLine("Specified link is empty!", ConsoleColor.Yellow);
							break;
						}

						_processor.ProcessFileLink(link);
						break;
					}
				default:
					{
						ConsoleUtil.WriteLine("Unknown command!", ConsoleColor.Yellow);
						break;
					}
			}
		}
	}
}

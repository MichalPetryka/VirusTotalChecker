using System;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
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
				case "datapath":
					{
						ConsoleUtil.WriteLine($"Data location: {Program.DataPath}");
						return;
					}
				case "lockinput":
					{
						string line = ConsoleUtil.ReadLineLock("Input your command and press enter to unlock output:");
						if (string.IsNullOrWhiteSpace(line))
						{
							ConsoleUtil.WriteLine("Cannot execute an empty command!", ConsoleColor.Yellow);
							return;
						}
						// ReSharper disable once TailRecursiveCall
						ProcessCommand(line.Split(" ", StringSplitOptions.RemoveEmptyEntries));
						return;
					}
				case "eicar":
					{
						const string eicar = "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F";
						_processor.ProcessFile(eicar, eicar);
						return;
					}
				case "scan":
					{
						if (command.Length < 2)
						{
							ConsoleUtil.WriteLine("You need to specify the desired file!", ConsoleColor.Yellow);
							return;
						}

						string cmd = command[1];
						if (string.IsNullOrWhiteSpace(cmd))
						{
							ConsoleUtil.WriteLine("Specified path is empty!", ConsoleColor.Yellow);
							return;
						}

						string path = Path.GetFullPath(cmd);
						if (!File.Exists(path))
						{
							ConsoleUtil.WriteLine($"File {path} does not exist!", ConsoleColor.Yellow);
							return;
						}

						_processor.ProcessFile(path);
						return;
					}
				case "scandirectory":
					{
						if (command.Length < 2)
						{
							ConsoleUtil.WriteLine("You need to specify the desired directory!",
								ConsoleColor.Yellow);
							return;
						}

						string cmd = command[1];
						if (string.IsNullOrWhiteSpace(cmd))
						{
							ConsoleUtil.WriteLine("Specified path is empty!", ConsoleColor.Yellow);
							return;
						}

						string path = Path.GetFullPath(cmd);
						if (!Directory.Exists(path))
						{
							ConsoleUtil.WriteLine($"Directory {path} does not exist!", ConsoleColor.Yellow);
							return;
						}

						string filter = "*";
						if (command.Length >= 3)
							filter = command[2];

						bool recursive = true;
						if (command.Length >= 4)
							recursive = bool.Parse(command[3]);

						_processor.ProcessDirectory(path, filter, recursive);
						return;
					}
				case "scanhash":
					{
						if (command.Length < 2)
						{
							ConsoleUtil.WriteLine("You need to specify a hash!", ConsoleColor.Yellow);
							return;
						}

						string hash = command[1];
						if (string.IsNullOrWhiteSpace(hash))
						{
							ConsoleUtil.WriteLine("Specified hash is empty!", ConsoleColor.Yellow);
							return;
						}

						_processor.ProcessFile(hash, hash);
						return;
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
								ConsoleUtil.WriteLine($"Failed to scan {process.ProcessName}. Error: {ex.GetErrorMessage()}", ConsoleColor.Red);
							}
						return;
					}
				case "scanprocess":
					{
						if (command.Length < 2)
						{
							ConsoleUtil.WriteLine("You need to specify the desired process id!", ConsoleColor.Yellow);
							return;
						}

						string id = command[1];
						if (string.IsNullOrWhiteSpace(id))
						{
							ConsoleUtil.WriteLine("Specified id is empty!", ConsoleColor.Yellow);
							return;
						}

						if (!int.TryParse(id, out int pid))
						{
							ConsoleUtil.WriteLine("Specified id isn't a valid number!", ConsoleColor.Yellow);
							return;
						}

						bool scanSubmodules = false;
						if (command.Length >= 3)
							scanSubmodules = bool.Parse(command[2]);

						Process process = Process.GetProcessById(pid);
						_processor.ProcessFile(process.MainModule!.FileName);
						if (scanSubmodules)
							foreach (ProcessModule module in process.Modules)
								_processor.ProcessFile(module.FileName);
						return;
					}
				case "scanfilelink":
					{
						if (command.Length < 2)
						{
							ConsoleUtil.WriteLine("You need to specify the desired link!", ConsoleColor.Yellow);
							return;
						}

						string link = command[1];
						if (string.IsNullOrWhiteSpace(link))
						{
							ConsoleUtil.WriteLine("Specified link is empty!", ConsoleColor.Yellow);
							return;
						}

						_processor.ProcessFileLink(link);
						return;
					}
				default:
					{
						ConsoleUtil.WriteLine("Unknown command!", ConsoleColor.Yellow);
						return;
					}
			}
		}
	}
}

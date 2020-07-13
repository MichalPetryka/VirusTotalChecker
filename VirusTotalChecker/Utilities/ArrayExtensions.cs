using System.Text;

namespace VirusTotalChecker.Utilities
{
	public static class ArrayExtensions
	{
		public static string ToHexString(this byte[] array)
		{
			StringBuilder sb = new StringBuilder(array.Length * 2);
			foreach (byte b in array)
				sb.Append(b.ToString("X2"));

			return sb.ToString();
		}
	}
}

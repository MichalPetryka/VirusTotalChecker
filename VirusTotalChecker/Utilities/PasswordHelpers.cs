using System;
using System.Buffers;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace VirusTotalChecker.Utilities
{
	public static class PasswordHelpers
	{
		private static readonly UTF8Encoding Encoding = new UTF8Encoding(false);

		public static string EncryptString(string plainText, string key)
		{
			using (Aes aes = Aes.Create())
			{
				aes.Key = Encoding.GetBytes(key);
				byte[] array = ArrayPool<byte>.Shared.Rent(Encoding.GetMaxByteCount(plainText.Length));
				int length = Encoding.GetBytes(plainText, array);
				byte[] encrypted;
				using (ICryptoTransform transform = aes.CreateEncryptor())
					encrypted = transform.TransformFinalBlock(array, 0, length);
				ArrayPool<byte>.Shared.Return(array);
				return Convert.ToBase64String(encrypted);
			}
		}

		public static string DecryptString(string cipherText, string key)
		{
			byte[] buffer = Convert.FromBase64String(cipherText);
			using (Aes aes = Aes.Create())
			{
				aes.Key = Encoding.GetBytes(key);
				using (ICryptoTransform transform = aes.CreateDecryptor())
					return Encoding.GetString(transform.TransformFinalBlock(buffer, 0, buffer.Length));
			}
		}

		public static string GetSha512(string text)
		{
			using (SHA512 sha = SHA512.Create())
				return sha.ComputeHash(Encoding.GetBytes(text)).ToHexString();
		}
	}
}

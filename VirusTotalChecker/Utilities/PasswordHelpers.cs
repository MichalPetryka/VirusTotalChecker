using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;

namespace VirusTotalChecker.Utilities
{
	public static class PasswordHelpers
	{
		private static readonly UTF8Encoding Encoding = new UTF8Encoding(false);

		public static string Encrypt(string plainText, string password)
		{
			using (Aes aes = Aes.Create())
			{
				aes!.Key = GetSha256Bytes(password);
				ArraySegment<byte> buffer = Encoding.GetPooledBytes(plainText, out byte[] array);
				byte[] encrypted;
				using (ICryptoTransform transform = aes.CreateEncryptor())
					encrypted = transform.TransformFinalBlock(buffer.Array!, buffer.Offset, buffer.Count);
				ArrayPool<byte>.Shared.Return(array);
				return Convert.ToBase64String(encrypted);
			}
		}

		public static string Decrypt(string cipherText, string password)
		{
			byte[] buffer = Convert.FromBase64String(cipherText);
			using (Aes aes = Aes.Create())
			{
				aes!.Key = GetSha256Bytes(password);
				using (ICryptoTransform transform = aes.CreateDecryptor())
					return Encoding.GetString(transform.TransformFinalBlock(buffer, 0, buffer.Length));
			}
		}

		internal static byte[] GetSha256Bytes(string text)
		{
			using (SHA256 sha = SHA256.Create())
			{
				ArraySegment<byte> buffer = Encoding.GetPooledBytes(text, out byte[] array);
				byte[] result = sha.ComputeHash(buffer.Array!, buffer.Offset, buffer.Count);
				ArrayPool<byte>.Shared.Return(array);
				return result;
			}
		}

		public static string GetSha512(string text)
		{
			using (SHA512 sha = SHA512.Create())
			{
				ArraySegment<byte> buffer = Encoding.GetPooledBytes(text, out byte[] array);
				string result = sha.ComputeHash(buffer.Array!, buffer.Offset, buffer.Count).ToHexString();
				ArrayPool<byte>.Shared.Return(array);
				return result;
			}
		}

		private static ArraySegment<byte> GetPooledBytes(this Encoding encoding, string s, out byte[] array)
		{
			array = ArrayPool<byte>.Shared.Rent(encoding.GetMaxByteCount(s.Length));
			return new ArraySegment<byte>(array, 0, encoding.GetBytes(s, array));
		}
	}
}

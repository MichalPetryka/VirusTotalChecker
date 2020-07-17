using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;

namespace VirusTotalChecker.Utilities
{
	public static class PasswordHelpers
	{
		private static readonly UTF8Encoding Encoding = new UTF8Encoding(false);
		private static readonly RNGCryptoServiceProvider _rng = new RNGCryptoServiceProvider();

		private const int InterationsNumber = 2000;
		private const int TagLength = 16;
		private const int NonceLength = 12;
		private const int SaltLength = 32;

		public static string Encrypt(string plainText, string password)
		{
			byte[] tag = ArrayPool<byte>.Shared.Rent(TagLength);
			byte[] saltArray = ArrayPool<byte>.Shared.Rent(SaltLength);
			byte[] nonceArray = ArrayPool<byte>.Shared.Rent(NonceLength);

			ArraySegment<byte> nonce = new ArraySegment<byte>(nonceArray, 0, NonceLength);
			ArraySegment<byte> salt = new ArraySegment<byte>(saltArray, 0, SaltLength);

			_rng.GetBytes(nonce);
			_rng.GetBytes(salt);
			string b64Output;

			byte[] key = DeriveEncryptionKey(password, salt, InterationsNumber, 32);

			using (AesGcm aes = new AesGcm(key))
			{
				ArraySegment<byte> plaintext = Encoding.GetPooledBytes(plainText, out byte[] array);
				byte[] ciphertextArray = ArrayPool<byte>.Shared.Rent(plaintext.Count);
				ArraySegment<byte> ciphertext = new ArraySegment<byte>(ciphertextArray, 0, plaintext.Count);
				aes.Encrypt(nonce, plaintext, ciphertext, tag);

				ArrayPool<byte>.Shared.Return(array);

				byte[] output = ArrayPool<byte>.Shared.Rent(TagLength + NonceLength + SaltLength + ciphertext.Count);
				Array.Copy(tag, 0, output, 0, TagLength);
				Array.Copy(nonceArray, 0, output, TagLength, NonceLength);
				Array.Copy(saltArray, 0, output, NonceLength + TagLength, SaltLength);
				Array.Copy(ciphertext.Array!, 0, output, NonceLength + TagLength + SaltLength, ciphertext.Count);

				b64Output = Convert.ToBase64String(new ArraySegment<byte>(output, 0, TagLength + NonceLength + SaltLength + ciphertext.Count));

				ArrayPool<byte>.Shared.Return(output);
				ArrayPool<byte>.Shared.Return(ciphertextArray);
			}

			ArrayPool<byte>.Shared.Return(tag);
			ArrayPool<byte>.Shared.Return(saltArray);
			ArrayPool<byte>.Shared.Return(nonceArray);
			ArrayPool<byte>.Shared.Return(key);

			return b64Output;
		}

		public static string Decrypt(string ciphertext, string password)
		{
			byte[] buffer = Convert.FromBase64String(ciphertext);

			ArraySegment<byte> tag = new ArraySegment<byte>(buffer, 0, TagLength);
			ArraySegment<byte> nonce = new ArraySegment<byte>(buffer, TagLength, NonceLength);
			ArraySegment<byte> salt = new ArraySegment<byte>(buffer, NonceLength + TagLength, SaltLength);
			ArraySegment<byte> data = new ArraySegment<byte>(buffer, NonceLength + TagLength + SaltLength, buffer.Length - TagLength - NonceLength - SaltLength);
			byte[] plainArray = ArrayPool<byte>.Shared.Rent(data.Count);
			ArraySegment<byte> plainData = new ArraySegment<byte>(plainArray, 0, data.Count);

			byte[] key = DeriveEncryptionKey(password, salt.ToArray(), InterationsNumber, 32);

			using (AesGcm aes = new AesGcm(key))
			{
				aes.Decrypt(nonce, data, tag, plainData);
			}

			string plainText = Encoding.GetString(plainData);

			ArrayPool<byte>.Shared.Return(plainArray);
			return plainText;
		}

		private static byte[] DeriveEncryptionKey(string password, ArraySegment<byte> salt, int iterations, int outputBytes)
		{
			using Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(password, salt.ToArray(), iterations, HashAlgorithmName.SHA512);
			return pbkdf2.GetBytes(outputBytes);
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

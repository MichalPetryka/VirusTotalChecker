using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;

namespace VirusTotalChecker.Utilities
{
	public static class PasswordHelpers
	{
		private static readonly UTF8Encoding Encoding = new UTF8Encoding(false);
		private static readonly RNGCryptoServiceProvider Rng = new RNGCryptoServiceProvider();

		private const int InterationsNumber = 2000;
		private const int TagLength = 16;
		private const int NonceLength = 12;
		private const int SaltLength = 32;

		public static string Encrypt(string plainText, string password)
		{
			byte[] salt = new byte[SaltLength];
			Rng.GetBytes(salt);
			byte[] key = DeriveEncryptionKey(password, salt, InterationsNumber, SaltLength);

			using (AesGcm aes = new AesGcm(key))
			{
				ReadOnlySpan<byte> plaintext = Encoding.GetPooledBytes(plainText, out byte[] array);
				Span<byte> nonce = ArrayPool<byte>.Shared.RentSegment(NonceLength, out byte[] nonceArray);
				Span<byte> ciphertext = ArrayPool<byte>.Shared.RentSegment(plaintext.Length, out byte[] ciphertextArray);
				Span<byte> tag = ArrayPool<byte>.Shared.RentSegment(TagLength, out byte[] tagArray);

				Rng.GetBytes(nonce);
				aes.Encrypt(nonce, plaintext, ciphertext, tag);

				ArrayPool<byte>.Shared.Return(array);

				Span<byte> output = ArrayPool<byte>.Shared.RentSegment(TagLength + NonceLength + SaltLength + ciphertext.Length, out byte[] outputArray);
				nonce.CopyTo(output.Slice(TagLength, NonceLength));
				ciphertext.CopyTo(output.Slice(NonceLength + TagLength + SaltLength, ciphertext.Length));
				tag.CopyTo(output.Slice(0, TagLength));
				salt.CopyTo(output.Slice(NonceLength + TagLength, SaltLength));

				ArrayPool<byte>.Shared.Return(nonceArray);
				ArrayPool<byte>.Shared.Return(ciphertextArray);
				ArrayPool<byte>.Shared.Return(tagArray);

				string b64Output = Convert.ToBase64String(output);
				ArrayPool<byte>.Shared.Return(outputArray);
				return b64Output;
			}
		}

		public static string Decrypt(string ciphertext, string password)
		{
			Span<byte> buffer = ArrayPool<byte>.Shared.RentSegment(ciphertext.Length, out byte[] baseArray);
			buffer = Convert.TryFromBase64String(ciphertext, buffer, out int written) ? buffer.Slice(0, written) : throw new Exception();

			ReadOnlySpan<byte> nonce = buffer.Slice(TagLength, NonceLength);
			ReadOnlySpan<byte> data = buffer.Slice(NonceLength + TagLength + SaltLength, buffer.Length - TagLength - NonceLength - SaltLength);
			ReadOnlySpan<byte> tag = buffer.Slice(0, TagLength);

			byte[] salt = buffer.Slice(NonceLength + TagLength, SaltLength).ToArray();
			byte[] key = DeriveEncryptionKey(password, salt, InterationsNumber, SaltLength);

			Span<byte> plainData = ArrayPool<byte>.Shared.RentSegment(data.Length, out byte[] plainArray);
			using (AesGcm aes = new AesGcm(key))
				aes.Decrypt(nonce, data, tag, plainData);

			ArrayPool<byte>.Shared.Return(baseArray);
			string plainText = Encoding.GetString(plainData);
			ArrayPool<byte>.Shared.Return(plainArray);
			return plainText;
		}

		private static byte[] DeriveEncryptionKey(string password, byte[] salt, int iterations, int outputBytes)
		{
			using (Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA512))
				return pbkdf2.GetBytes(outputBytes);
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

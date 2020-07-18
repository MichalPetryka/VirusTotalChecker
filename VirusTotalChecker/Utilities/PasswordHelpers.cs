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
		private const int KeyHashLength = 512 / 8;

		public static bool IsValid(string password, out string message)
		{
			if (password == null)
			{
				message = "Password can't be null";
				return false;
			}

			if (password.Length < 8)
			{
				message = "Password must be at least 8 characters long";
				return false;
			}

			bool containsLetters = false;
			bool containsNumbers = false;
			bool containsSymbols = false;
			for (int i = 0; i < password.Length; i++)
			{
				char c = password[i];
				if (c == '\0')
				{
					message = "Password can't contain null character";
					return false;
				}

				if (char.IsWhiteSpace(c))
				{
					message = "Password can't contain whitespaces";
					return false;
				}

				if (char.IsLetter(c))
					containsLetters = true;

				if (char.IsDigit(c))
					containsNumbers = true;

				if (char.IsSymbol(c) || char.IsPunctuation(c))
					containsSymbols = true;
			}

			if (!containsLetters)
			{
				message = "Password must contain a letter";
				return false;
			}

			if (!containsNumbers)
			{
				message = "Password must contain a digit";
				return false;
			}

			if (!containsSymbols)
			{
				message = "Password must contain a symbol";
				return false;
			}

			message = null;
			return true;
		}

		public static string Encrypt(string plainText, string password)
		{
			byte[] salt = new byte[SaltLength];
			Rng.GetBytes(salt);
			byte[] key = DeriveEncryptionKey(password, salt, InterationsNumber, SaltLength);

			byte[] keyHash;
			using (SHA512 sha = SHA512.Create())
				keyHash = sha.ComputeHash(key);

			using (AesGcm aes = new AesGcm(key))
			{
				ReadOnlySpan<byte> plaintext = Encoding.GetPooledBytes(plainText, out byte[] array);
				Span<byte> nonce = ArrayPool<byte>.Shared.RentSegment(NonceLength, out byte[] nonceArray);
				Span<byte> ciphertext = ArrayPool<byte>.Shared.RentSegment(plaintext.Length, out byte[] ciphertextArray);
				Span<byte> tag = ArrayPool<byte>.Shared.RentSegment(TagLength, out byte[] tagArray);

				Rng.GetBytes(nonce);
				aes.Encrypt(nonce, plaintext, ciphertext, tag);

				ArrayPool<byte>.Shared.Return(array);

				Span<byte> output = ArrayPool<byte>.Shared.RentSegment(keyHash.Length + TagLength + NonceLength + SaltLength + ciphertext.Length, out byte[] outputArray);
				keyHash.CopyTo(output.Slice(0, keyHash.Length));
				nonce.CopyTo(output.Slice(keyHash.Length + TagLength, NonceLength));
				ciphertext.CopyTo(output.Slice(keyHash.Length + NonceLength + TagLength + SaltLength, ciphertext.Length));
				tag.CopyTo(output.Slice(keyHash.Length, TagLength));
				salt.CopyTo(output.Slice(keyHash.Length + NonceLength + TagLength, SaltLength));

				ArrayPool<byte>.Shared.Return(nonceArray);
				ArrayPool<byte>.Shared.Return(ciphertextArray);
				ArrayPool<byte>.Shared.Return(tagArray);

				string b64Output = Convert.ToBase64String(output);
				ArrayPool<byte>.Shared.Return(outputArray);
				return b64Output;
			}
		}

		public static bool Decrypt(string ciphertext, string password, out string text)
		{
			Span<byte> buffer = ArrayPool<byte>.Shared.RentSegment(ciphertext.Length, out byte[] baseArray);
			buffer = Convert.TryFromBase64String(ciphertext, buffer, out int written) ? buffer.Slice(0, written) : throw new Exception();

			ReadOnlySpan<byte> nonce = buffer.Slice(KeyHashLength + TagLength, NonceLength);
			ReadOnlySpan<byte> data = buffer.Slice(KeyHashLength + NonceLength + TagLength + SaltLength, buffer.Length - TagLength - NonceLength - SaltLength - KeyHashLength);
			ReadOnlySpan<byte> tag = buffer.Slice(KeyHashLength, TagLength);

			byte[] salt = buffer.Slice(KeyHashLength + NonceLength + TagLength, SaltLength).ToArray();
			byte[] key = DeriveEncryptionKey(password, salt, InterationsNumber, SaltLength);

			using (SHA512 sha = SHA512.Create())
				if (!buffer.Slice(0, KeyHashLength).SequenceEqual(sha.ComputeHash(key)))
				{
					ArrayPool<byte>.Shared.Return(baseArray);
					text = default;
					return false;
				}

			Span<byte> plainData = ArrayPool<byte>.Shared.RentSegment(data.Length, out byte[] plainArray);
			using (AesGcm aes = new AesGcm(key))
				aes.Decrypt(nonce, data, tag, plainData);

			ArrayPool<byte>.Shared.Return(baseArray);
			text = Encoding.GetString(plainData);
			ArrayPool<byte>.Shared.Return(plainArray);
			return true;
		}

		private static byte[] DeriveEncryptionKey(string password, byte[] salt, int iterations, int outputBytes)
		{
			using (Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA512))
				return pbkdf2.GetBytes(outputBytes);
		}

		internal static ArraySegment<byte> GetPooledBytes(this Encoding encoding, string s, out byte[] array)
		{
			array = ArrayPool<byte>.Shared.Rent(encoding.GetMaxByteCount(s.Length));
			return new ArraySegment<byte>(array, 0, encoding.GetBytes(s, array));
		}
	}
}

using Newtonsoft.Json;
using VirusTotalChecker.Utilities;
using Xunit;
using Xunit.Abstractions;

namespace VirusTotalChecker.Tests
{
	public class StringEnumIgnoreCaseSerializerTests
	{
		private readonly ITestOutputHelper _output;
		public StringEnumIgnoreCaseSerializerTests(ITestOutputHelper output) => _output = output;

		private class EnumTestJsonClass
		{
			[JsonConverter(typeof(StringEnumIgnoreCaseConverter))]
			public LogCompressionType CompressionType { get; set; }
		}

		private class NotEnumArrayTestJsonClass
		{
			[JsonConverter(typeof(StringEnumIgnoreCaseConverter))]
			// ReSharper disable once UnusedAutoPropertyAccessor.Local
			public LogCompressionType[] CompressionType { get; set; }
		}

		private class NotEnumStringTestJsonClass
		{
			[JsonConverter(typeof(StringEnumIgnoreCaseConverter))]
			// ReSharper disable once UnusedAutoPropertyAccessor.Local
			public string CompressionType { get; set; }
		}

		[Theory]
		[InlineData(LogCompressionType.Gzip)]
		[InlineData(LogCompressionType.Brotli)]
		[InlineData(LogCompressionType.None)]
		[InlineData((LogCompressionType)(-50000))]
		[InlineData((LogCompressionType)50000)]
		public void SerializeAndDeserializeTest(LogCompressionType type)
		{
			string json = JsonConvert.SerializeObject(new EnumTestJsonClass { CompressionType = type });
			Assert.NotNull(json);
			Assert.NotEqual("", json);
			_output.WriteLine(json);
			Assert.Equal(type, JsonConvert.DeserializeObject<EnumTestJsonClass>(json).CompressionType);
		}

		[Theory]
		[InlineData(LogCompressionType.Gzip, "{\"CompressionType\":\"gzip\"}")]
		[InlineData(LogCompressionType.Brotli, "{\"CompressionType\":\"brotli\"}")]
		[InlineData(LogCompressionType.None, "{\"CompressionType\":\"none\"}")]
		[InlineData(LogCompressionType.Gzip, "{\"CompressionType\":\"GZIP\"}")]
		[InlineData(LogCompressionType.Brotli, "{\"CompressionType\":\"BROTLI\"}")]
		[InlineData(LogCompressionType.None, "{\"CompressionType\":\"NONE\"}")]
		[InlineData((LogCompressionType)(-50000), "{\"CompressionType\":-50000}")]
		[InlineData((LogCompressionType)50000, "{\"CompressionType\":50000}")]
		[InlineData((LogCompressionType)(-50000), "{\"CompressionType\":\"-50000\"}")]
		[InlineData((LogCompressionType)50000, "{\"CompressionType\":\"50000\"}")]
		public void DeserializeTest(LogCompressionType type, string json)
		{
			Assert.Equal(type, JsonConvert.DeserializeObject<EnumTestJsonClass>(json).CompressionType);
		}

		[Fact]
		public void NotEnumArraySerializeTest()
		{
			_output.WriteLine(Assert.Throws<StringEnumIgnoreCaseConverter.InvalidTypeException>(() =>
				JsonConvert.SerializeObject(
					new NotEnumArrayTestJsonClass { CompressionType = new[] { LogCompressionType.Gzip } })).Message);
		}

		[Fact]
		public void NotEnumArrayStringSerializeTest()
		{
			_output.WriteLine(Assert.Throws<StringEnumIgnoreCaseConverter.InvalidTypeException>(() =>
				JsonConvert.SerializeObject(
					// ReSharper disable once HeapView.BoxingAllocation
					new NotEnumStringTestJsonClass { CompressionType = LogCompressionType.Gzip.ToString() })).Message);
		}
	}
}

using System;
using Newtonsoft.Json;

namespace VirusTotalChecker.Utilities
{
	public class StringEnumIgnoreCaseConverter : JsonConverter
	{
		public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
		{
			if (value is Enum e)
				writer.WriteValue(e.ToString());
			else
				throw new InvalidTypeException(value.GetType());
		}

		public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
		{
			if (!objectType.IsEnum)
				throw new InvalidTypeException(objectType);
			switch (reader.TokenType)
			{
				case JsonToken.Null:
					{
						throw new Exception("Null enums are not supported!");
					}
				case JsonToken.Integer:
				case JsonToken.String:
					{
						return Enum.Parse(objectType, reader.Value!.ToString()!, true);
					}
				default:
					throw new ArgumentOutOfRangeException();
			}
		}

		public override bool CanConvert(Type objectType)
		{
			return objectType.IsEnum;
		}

		public class InvalidTypeException : Exception
		{
			public InvalidTypeException(Type type) : base($"This JsonSerializer doesn't support type: {type.Name}")
			{

			}
		}
	}
}

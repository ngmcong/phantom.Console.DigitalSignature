using System.Text;

public class Base64Converter
{
    /// <summary>
    /// Encodes a string to its Base64 representation.
    /// </summary>
    /// <param name="plainText">The string to encode.</param>
    /// <returns>The Base64 encoded string.</returns>
    public static string Base64Encode(string plainText)
    {
        var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
        return Convert.ToBase64String(plainTextBytes);
    }

    /// <summary>
    /// Decodes a Base64 encoded string to its original byte array representation.
    /// </summary>
    /// <param name="base64EncodedData">The Base64 encoded string.</param>
    /// <returns>The original decoded byte array.</returns>
    public static byte[] Base64ArrayDecode(string base64EncodedData)
    {

        try
        {
            return Convert.FromBase64String(base64EncodedData);
        }
        catch
        {
            throw;
        }
    }

    /// <summary>
    /// Decodes a Base64 encoded string to its original string representation.
    /// </summary>
    /// <param name="base64EncodedData">The Base64 encoded string.</param>
    /// <returns>The original decoded string.</returns>
    public static string Base64Decode(string base64EncodedData)
    {
        try
        {
            var base64EncodedBytes = Base64ArrayDecode(base64EncodedData);
            return Encoding.UTF8.GetString(base64EncodedBytes);
        }
        catch
        {
            throw;
        }
    }
}
using System.Security.Cryptography;
using System.Xml;

// Helper class to convert RSA parameters to/from XML strings
public static class RsaKeyConverter
{
    public static string ToXmlString(this RSAParameters key, bool includePrivate)
    {
        using (var stream = new System.IO.StringWriter())
        {
            using (var writer = XmlWriter.Create(stream)) // Fixed CS0144: Use XmlWriter.Create instead of new XmlWriter
            {
                writer.WriteStartElement("RSAKeyValue");

                if (key.Modulus != null) writer.WriteElementString("Modulus", Convert.ToBase64String(key.Modulus));
                if (key.Exponent != null) writer.WriteElementString("Exponent", Convert.ToBase64String(key.Exponent));

                if (includePrivate)
                {
                    if (key.P != null) writer.WriteElementString("P", Convert.ToBase64String(key.P));
                    if (key.Q != null) writer.WriteElementString("Q", Convert.ToBase64String(key.Q));
                    if (key.DP != null) writer.WriteElementString("DP", Convert.ToBase64String(key.DP));
                    if (key.DQ != null) writer.WriteElementString("DQ", Convert.ToBase64String(key.DQ));
                    if (key.InverseQ != null) writer.WriteElementString("InverseQ", Convert.ToBase64String(key.InverseQ));
                    if (key.D != null) writer.WriteElementString("D", Convert.ToBase64String(key.D));
                }

                writer.WriteEndElement();
                writer.Flush(); // Ensure all data is written to the stream
                return Base64Converter.Base64Encode(stream.ToString());
            }
        }
    }

    public static RSAParameters FromXmlString(string xmlString)
    {
        xmlString = Base64Converter.Base64Decode(xmlString);
        var parameters = new RSAParameters();
        using (var reader = XmlReader.Create(new System.IO.StringReader(xmlString))) // Fixed CS0144: Use XmlReader.Create instead of new XmlReader
        {
            reader.MoveToContent();
            while (reader.Read())
            {
                if (reader.NodeType == XmlNodeType.Element)
                {
                    switch (reader.Name)
                    {
                        case "Modulus": parameters.Modulus = Convert.FromBase64String(reader.ReadElementContentAsString()); break;
                        case "P": parameters.P = Convert.FromBase64String(reader.ReadElementContentAsString()); break;
                        case "DP": parameters.DP = Convert.FromBase64String(reader.ReadElementContentAsString()); break;
                        case "InverseQ": parameters.InverseQ = Convert.FromBase64String(reader.ReadElementContentAsString()); break;
                    }
                }
            }
        }

        XmlDocument xmlDocument = new XmlDocument();
        xmlDocument.LoadXml(xmlString);
        var childNodes = xmlDocument.GetElementsByTagName("RSAKeyValue")[0]!.ChildNodes.Cast<XmlNode>();
        foreach (var item in childNodes)
        {
            switch (item.Name)
            {
                case "Exponent": parameters.Exponent = Convert.FromBase64String(childNodes.First(e => e.Name == "Exponent").InnerText); break;
                case "Q": parameters.Q = Convert.FromBase64String(childNodes.First(e => e.Name == "Q").InnerText); break;
                case "DQ": parameters.DQ = Convert.FromBase64String(childNodes.First(e => e.Name == "DQ").InnerText); break;
                case "D": parameters.D = Convert.FromBase64String(childNodes.First(e => e.Name == "D").InnerText); break;
            }
        }

        return parameters;
    }
}
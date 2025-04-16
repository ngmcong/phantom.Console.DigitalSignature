using System.Security.Cryptography;
using System.Text;

internal class DigitalSignatureExample
{
    internal static void Main(string[] args)
    {
        RSAParameters publicKey;
        RSAParameters privateKey;
        // Generate a new RSA key pair
        using (RSA rsa = RSA.Create())
        {
            // Generate a new RSA key pair with a specified key size (e.g., 2048 bits)
            rsa.KeySize = 2048;

            // Get the public and private keys
            publicKey = rsa.ExportParameters(false);
            privateKey = rsa.ExportParameters(true);
        }
        #region Tests
        // Convert public key to XML string
        string publicKeyXml = publicKey.ToXmlString(false);
        publicKey = RsaKeyConverter.FromXmlString(publicKeyXml);
        // Convert private key to XML string
        string privateKeyXml = privateKey.ToXmlString(true);
        privateKey = RsaKeyConverter.FromXmlString(privateKeyXml);
        #endregion Tests

        // The data to be signed
        string originalData = "This is the data I want to digitally sign.";

        // Sign the data
        var signatureString = SignData(originalData, privateKey);
        Console.WriteLine($"Digital Signature (Base64): {signatureString}");

        // Verify the signature
        Console.WriteLine($"Is Signature Valid: {VerifyData(originalData, signatureString, publicKey)}");

        // Tamper with the data
        Console.WriteLine($"Is Tampered Signature Valid: {VerifyData("This data has been modified!", signatureString, publicKey)}");
    }

    // Function to sign data using RSA
    private static string SignData(string originalData, RSAParameters privateKey)
    {
        byte[] dataToSign = Encoding.UTF8.GetBytes(originalData);
        using (RSA rsa = RSA.Create())
        {
            // Generate a new RSA key pair with a specified key size (e.g., 2048 bits)
            rsa.KeySize = 2048;
            rsa.ImportParameters(privateKey);

            // Use SHA256 for hashing before signing
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashValue = sha256.ComputeHash(dataToSign);

                // Sign the hash using PKCS#1 v1.5 padding
                return Convert.ToBase64String(rsa.SignHash(hashValue, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            }
        }
    }

    // Function to verify the digital signature using RSA
    private static bool VerifyData(string originalData, string signatureString, RSAParameters publicKey)
    {
        byte[] signedData = Encoding.UTF8.GetBytes(originalData);
        byte[] signature = Base64Converter.Base64ArrayDecode(signatureString);
        using (RSA rsa = RSA.Create())
        {
            // Generate a new RSA key pair with a specified key size (e.g., 2048 bits)
            rsa.KeySize = 2048;
            rsa.ImportParameters(publicKey);

            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashValue = sha256.ComputeHash(signedData);

                // Verify the signature using PKCS#1 v1.5 padding
                return rsa.VerifyHash(hashValue, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }
    }
}
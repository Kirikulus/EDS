using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

class Program
{
    static void Main()
    {
        string document = "This is the document to be signed";
        byte[] documentBytes = Encoding.UTF8.GetBytes(document);

        X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        X509Certificate2 certificate = null;

        string thumbprint = "ОТПЕЧАТОК";

        foreach (var cert in store.Certificates)
        {
            if (cert.Thumbprint.Equals(thumbprint, StringComparison.OrdinalIgnoreCase))
            {
                certificate = cert;
                break;
            }
        }

        store.Close();

        if (certificate == null)
        {
            Console.WriteLine("Certificate not found.");
            return;
        }

        byte[] signature;
        try
        {
            signature = SignData(documentBytes, certificate);
            Console.WriteLine("Document: " + document);
            Console.WriteLine("Signature: " + Convert.ToBase64String(signature));
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error signing data: " + ex.Message);
            return;
        }

        bool isValid = VerifySignature(documentBytes, signature, certificate);

        Console.WriteLine("Signature is valid: " + isValid);
    }

    static byte[] SignData(byte[] data, X509Certificate2 certificate)
    {
        return ProcessDataWithRSA<byte[]>(data, certificate, true);
    }

    static bool VerifySignature(byte[] data, byte[] signature, X509Certificate2 certificate)
    {
        byte[] hash = ComputeHash(data);
        return ProcessDataWithRSA<bool>(hash, certificate, false, signature);
    }

    static T ProcessDataWithRSA<T>(byte[] data, X509Certificate2 certificate, bool sign, byte[] signature = null)
    {
        using (RSA rsa = sign ? certificate.GetRSAPrivateKey() : certificate.GetRSAPublicKey())
        {
            if (rsa == null)
            {
                throw new InvalidOperationException("Certificate does not have the required key.");
            }

            if (sign)
            {
                byte[] hash = ComputeHash(data);
                return (T)(object)rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
            else
            {
                bool isValid = rsa.VerifyHash(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                return (T)(object)isValid;
            }
        }
    }

    static byte[] ComputeHash(byte[] data)
    {
        using (SHA256 sha256 = SHA256.Create())
        {
            return sha256.ComputeHash(data);
        }
    }
}
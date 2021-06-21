using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace GenerateSignature
{
    class Program
    {
        static void Main(string[] args)
        {

            
            string privateKeyFromFile = File.ReadAllText("private.key");           
            var privateKeyService = GetClientPrivateKeyFromRest(privateKeyFromFile);
            var key = privateKeyService.ExportParameters(true);

            string bodyDataFromFile = File.ReadAllText("BodyData.json");
            //var signedData = SignData(bodyDataFromFile, key);
            var signedData = SignData("ca486d2d7c2f4d5b908bec35619e7b194dcd0e57fa0c48e8b4d8c4b7d38324721624274419"+ "?beginDate=2019-01-01&endDate=2021-06-20&itemCount=2", key);

            Console.WriteLine(signedData);
            Console.ReadLine();
            
        }


        static string SignData(string data, RSAParameters key)
        {
            // Create a UnicodeEncoder to convert between byte array and string.
            var byteConverter = new ASCIIEncoding();
            var originalData = byteConverter.GetBytes(data);

            try
            {
                // Create a new instance of RSACryptoServiceProvider using the 
                // key from RSAParameters.  
                var rsaProvider = new RSACryptoServiceProvider();

                rsaProvider.ImportParameters(key);

                // Hash and sign the data. Pass a new instance of SHA1CryptoServiceProvider
                // to specify the use of SHA1 for hashing.
                var signedData = rsaProvider.SignData(originalData, "SHA256");
                return Convert.ToBase64String(signedData);

            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);
            }
            return null;
        }

        static RSACryptoServiceProvider GetClientPrivateKeyFromRest(string privateKey)
        {
            using (TextReader privateKeyTextReader = new StringReader(privateKey))
            {
                var readKeyPair = (AsymmetricCipherKeyPair)new PemReader(privateKeyTextReader).ReadObject();

                var privateKeyParams = ((RsaPrivateCrtKeyParameters)readKeyPair.Private);
                var cryptoServiceProvider = new RSACryptoServiceProvider();
                var parameters = new RSAParameters
                {
                    Modulus = privateKeyParams.Modulus.ToByteArrayUnsigned(),
                    P = privateKeyParams.P.ToByteArrayUnsigned(),
                    Q = privateKeyParams.Q.ToByteArrayUnsigned(),
                    DP = privateKeyParams.DP.ToByteArrayUnsigned(),
                    DQ = privateKeyParams.DQ.ToByteArrayUnsigned(),
                    InverseQ = privateKeyParams.QInv.ToByteArrayUnsigned(),
                    D = privateKeyParams.Exponent.ToByteArrayUnsigned(),
                    Exponent = privateKeyParams.PublicExponent.ToByteArrayUnsigned()
                };

                cryptoServiceProvider.ImportParameters(parameters);
                return cryptoServiceProvider;
            }
        }

    }
}

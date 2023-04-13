//The MIT License(MIT)
//
//Copyright(c) [2018] [Pedro Henrique Vasconcellos]
//
//Permission is hereby granted, free of charge, to any person obtaining a copy of
//this software and associated documentation files (the "Software"), to deal in
//the Software without restriction, including without limitation the rights to
//use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
//the Software, and to permit persons to whom the Software is furnished to do so,
//subject to the following conditions:
//
//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
//FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
//COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
//IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
//CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Xml.Serialization;

namespace Vasconcellos.Crypt
{
    /// <summary>
    /// CryptographyRSA
    /// Note: RSA encryption is only mean for small amounts of data, the amount of data you can encrypt is dependent on the size of the key you are using.
    /// Note: There's a good reason for this, asymmetric encryption is computationally expensive. 
    ///       If you want to encrypt large amounts of data you should be using symmetric encryption.
    /// </summary>
    public class CryptographyRSA
    {
        private readonly RSACryptoServiceProvider ServiceProvider;

        private readonly RSAParameters PrivateKey;

        public readonly RSAParameters PublicKey;

        public readonly bool OAEP;

        public readonly BitsEnum Bits;

        public enum BitsEnum
        {
            bit384 = 384,
            bit512 = 512,
            bit1024 = 1024,
            bit2048 = 2048,
            bit4096 = 4096,
            bit8192 = 8192,
            bit16384 = 16384
        }

        /// <summary>
        /// CryptographyRSA constructor
        /// </summary>
        /// <param name="keySize"></param>
        /// <param name="OAEP"></param>
        public CryptographyRSA(BitsEnum bits, bool oAEP = false)
        {
            this.Bits = bits;
            this.ServiceProvider = new RSACryptoServiceProvider((int)this.Bits);
            this.PrivateKey = this.ServiceProvider.ExportParameters(true);
            this.PublicKey = this.ServiceProvider.ExportParameters(false);
            this.OAEP = oAEP;
        }

        /// <summary>
        /// CryptographyRSA constructor
        /// </summary>
        /// <param name="privateKey"></param>
        /// <param name="publicKey"></param>
        /// <param name="OAEP"></param>
        public CryptographyRSA(RSAParameters privateKey, RSAParameters publicKey, bool oAEP = false)
        {
            if (privateKey.Modulus.Length != publicKey.Modulus.Length)
                throw new ArgumentException("Private key size differs from public key!");

            this.Bits = (BitsEnum)(privateKey.Modulus.Length * 8);
            this.ServiceProvider = new RSACryptoServiceProvider((int)this.Bits);
            this.PrivateKey = privateKey;
            this.PublicKey = publicKey;
            this.OAEP = oAEP;
        }

        /// <summary>
        /// PublicKeyToXML
        /// </summary>
        /// <returns>string</returns>
        public string PublicKeyToXML()
        {
            using (var sw = new StringWriter())
            {
                var xs = new XmlSerializer(typeof(RSAParameters));
                xs.Serialize(sw, this.PublicKey);
                return sw.ToString();
            }
        }

        /// <summary>
        /// RSAKeyToXML
        /// </summary>
        /// <returns>string</returns>
        public string RSAKeyToXML(RSAParameters RSAKey)
        {
            using (var sw = new StringWriter())
            {
                var xs = new XmlSerializer(typeof(RSAParameters));
                xs.Serialize(sw, RSAKey);
                return sw.ToString();
            }
        }

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns>byte[]</returns>
        public byte[] Encrypt(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0) return null;
            this.ServiceProvider.ImportParameters(this.PublicKey);
            var response = this.ServiceProvider.Encrypt(bytes, this.OAEP);
            return response;
        }

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="text"></param>
        /// <returns>string</returns>
        public string Encrypt(string text)
        {
            if (string.IsNullOrEmpty(text)) return null;
            var response = this.Encrypt(Encoding.Unicode.GetBytes(text));
            return Convert.ToBase64String(response);
        }

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns>byte[]</returns>
        public byte[] Decrypt(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0) return null;
            this.ServiceProvider.ImportParameters(this.PrivateKey);
            var response = this.ServiceProvider.Decrypt(bytes, this.OAEP);
            return response;
        }

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="text"></param>
        /// <returns>string</returns>
        public string Decrypt(string text)
        {
            if (string.IsNullOrEmpty(text)) return null;
            var response = this.Decrypt(Convert.FromBase64String(text));
            return Encoding.Unicode.GetString(response);
        }
    }
}

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
    /// </summary>
    public class CryptographyRSA
    {
        private readonly RSACryptoServiceProvider _serviceProvider;
        private readonly RSAParameters _privateKey;
        private readonly RSAParameters _publicKey;
        private readonly bool _doOAEPPadding;

        public enum BitsEnum
        {
            bit128 = 128,
            bit256 = 256,
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
        /// <param name="doOAEPPadding"></param>
        public CryptographyRSA(BitsEnum keySize, bool doOAEPPadding = false)
        {
            this._serviceProvider = new RSACryptoServiceProvider((int)keySize);
            this._privateKey = this._serviceProvider.ExportParameters(true);
            this._publicKey = this._serviceProvider.ExportParameters(false);
            this._doOAEPPadding = doOAEPPadding;
        }

        /// <summary>
        /// PublicKeyXML
        /// </summary>
        /// <returns>string</returns>
        public string PublicKeyXML()
        {
            using (var sw = new StringWriter())
            {
                var xs = new XmlSerializer(typeof(RSAParameters));
                xs.Serialize(sw, this._publicKey);
                return sw.ToString();
            }
        }

        /// <summary>
        /// PrivateKeyXML
        /// </summary>
        /// <returns>string</returns>
        public string PrivateKeyXML()
        {
            using (var sw = new StringWriter())
            {
                var xs = new XmlSerializer(typeof(RSAParameters));
                xs.Serialize(sw, this._privateKey);
                return sw.ToString();
            }
        }

        /// <summary>
        /// GetPublicKey
        /// </summary>
        /// <returns>RSAParameters</returns>
        public RSAParameters GetPublicKey()
        {
            return this._publicKey;
        }

        /// <summary>
        /// GetPrivateKey
        /// </summary>
        /// <returns>RSAParameters</returns>
        public RSAParameters GetPrivateKey()
        {
            return this._privateKey;
        }

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="text"></param>
        /// <param name="publicKey"></param>
        /// <param name="doOAEPPadding"></param>
        /// <returns>string</returns>
        public string Encrypt(string text, RSAParameters publicKey, bool doOAEPPadding = false)
        {
            if (string.IsNullOrEmpty(text)) return null;
            this._serviceProvider.ImportParameters(publicKey);
            var data = Encoding.Unicode.GetBytes(text);
            var encryptedText = this._serviceProvider.Encrypt(data, doOAEPPadding);
            return Convert.ToBase64String(encryptedText);
        }

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="encryptedText"></param>
        /// <param name="privateKey"></param>
        /// <param name="doOAEPPadding"></param>
        /// <returns>string</returns>
        public string Decrypt(string encryptedText, RSAParameters privateKey, bool doOAEPPadding = false)
        {
            if (string.IsNullOrEmpty(encryptedText)) return null;
            var dataBytes = Convert.FromBase64String(encryptedText);
            this._serviceProvider.ImportParameters(privateKey);
            var text = this._serviceProvider.Decrypt(dataBytes, doOAEPPadding);
            return Encoding.Unicode.GetString(text);
        }

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="text"></param>
        /// <returns>string</returns>
        public string Encrypt(string text)
        {
            if (string.IsNullOrEmpty(text)) return null;
            this._serviceProvider.ImportParameters(this._publicKey);
            var data = Encoding.Unicode.GetBytes(text);
            var encryptedText = this._serviceProvider.Encrypt(data, this._doOAEPPadding);
            return Convert.ToBase64String(encryptedText);
        }

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="encryptedText"></param>
        /// <returns>string</returns>
        public string Decrypt(string encryptedText)
        {
            if (string.IsNullOrEmpty(encryptedText)) return null;
            var dataBytes = Convert.FromBase64String(encryptedText);
            this._serviceProvider.ImportParameters(this._privateKey);
            var text = this._serviceProvider.Decrypt(dataBytes, this._doOAEPPadding);
            return Encoding.Unicode.GetString(text);
        }
    }
}

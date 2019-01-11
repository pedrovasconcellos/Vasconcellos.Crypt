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
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Vasconcellos.Crypt
{
    /// <summary>
    /// CryptographyAES
    /// </summary>
    public class CryptographyAES
    {
        private readonly string Key;

        private readonly byte[] IV;

        public readonly bool Initialized;

        public readonly BitsEnum Bits;

        public enum BitsEnum
        {
            bit128 = 128,
            bit192 = 192,
            bit256 = 256,
        }

        /// <summary>
        /// Cryptography AES constructor
        /// </summary>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <param name="bits"></param>
        public CryptographyAES(string key, byte[] iv = null, BitsEnum bits = BitsEnum.bit256)
        {
            int numberKeyBytes = ((int)bits) / 8;
            int numberIVBytes = 16;

            if (iv != null && iv.Length != numberIVBytes) throw new ArgumentException($"The IV must contain {numberIVBytes} positions.");

            if (string.IsNullOrEmpty(key)) throw new ArgumentException("The key can not null or empty.");
            if (key.Length < numberKeyBytes) throw new ArgumentException($"Key must contain {numberKeyBytes} or more positions.");
            if (!key.Any(c => char.IsDigit(c))) throw new ArgumentException("The key must contain at least one digit.");
            if (!key.Any(c => char.IsUpper(c))) throw new ArgumentException("The key must contain at least one upperrcase letter.");
            if (!key.Any(c => char.IsLower(c))) throw new ArgumentException("The key must contain at least one lowercase letter.");

            this.IV = (iv ?? (new byte[16] { 0x12, 0x23, 0x45, 0x56, 0x78, 0xff, 0xab, 0x89, 0xFF, 0x74, 0x19, 0x33, 0x53, 0x4C, 0xA7, 0xB3 }));
            this.Key = key;
            this.Bits = bits;
            this.Initialized = !(this.IV == null && string.IsNullOrEmpty(this.Key) && !Enum.IsDefined(typeof(BitsEnum), this.Bits));
        }

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns>byte[]</returns>
        public byte[] Encrypt(byte[] bytes)
        {
            try
            {
                if (bytes == null || bytes.Length == 0) return null;
                if (Initialized == false) throw new ArgumentException($"The class {nameof(CryptographyAES)} was not initialized.");

                byte[] byteKey = Convert.FromBase64String(this.Key);

                using (Rijndael rijndael = new RijndaelManaged
                {
                    KeySize = (int)this.Bits
                })
                {
                    MemoryStream mStream = new MemoryStream();
                    CryptoStream encryptor = new CryptoStream(
                        mStream,
                        rijndael.CreateEncryptor(byteKey, this.IV),
                        CryptoStreamMode.Write);

                    encryptor.Write(bytes, 0, bytes.Length);
                    encryptor.FlushFinalBlock();

                    return mStream.ToArray();
                }
            }
            catch (Exception e)
            {
                throw new Exception(e.Message);
            }
        }

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="text"></param>
        /// <returns>string</returns>
        public string Encrypt(string text)
        {
            if (string.IsNullOrEmpty(text)) return null;
            byte[] byteText = new UTF8Encoding().GetBytes(text);
            return Convert.ToBase64String(Encrypt(byteText));
        }

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns>byte[]</returns>
        public byte[] Decrypt(byte[] bytes)
        {
            try
            {
                if (bytes == null || bytes.Length == 0) return null;
                if (Initialized == false) throw new ArgumentException($"The class {nameof(CryptographyAES)} was not initialized.");

                byte[] byteKey = Convert.FromBase64String(this.Key);

                using (Rijndael rijndael = new RijndaelManaged
                {
                    KeySize = (int)this.Bits
                })
                {
                    MemoryStream mStream = new MemoryStream();

                    CryptoStream decryptor = new CryptoStream(
                        mStream,
                        rijndael.CreateDecryptor(byteKey, this.IV),
                        CryptoStreamMode.Write);

                    decryptor.Write(bytes, 0, bytes.Length);
                    decryptor.FlushFinalBlock();

                    return mStream.ToArray();
                }
            }
            catch (Exception e)
            {
                throw new Exception(e.Message);
            }
        }

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="text"></param>
        /// <returns>string</returns>
        public string Decrypt(string text)
        {
            if (string.IsNullOrEmpty(text)) return null;
            byte[] byteText = Convert.FromBase64String(text);
            return new UTF8Encoding().GetString(Decrypt(byteText));
        }

        /// <summary>
        /// GenerateIV
        /// </summary>
        /// <returns>byte[16]</returns>
        public static byte[] GenerateIV()
        {
            var bytes = new byte[16];
            using (var crypto = new RNGCryptoServiceProvider())
            {
                crypto.GetBytes(bytes);
            }
            return bytes;
        }

        /// <summary>
        /// GenerateKey
        /// </summary>
        /// <param name="bits"></param>
        /// <returns>byte[BitsEnum / 8]</returns>
        public static string GenerateKey(BitsEnum bits = BitsEnum.bit256)
        {
            var bytes = new byte[(int)bits / 8];
            using (var crypto = new RNGCryptoServiceProvider())
            {
                crypto.GetBytes(bytes);
            }
            return Convert.ToBase64String(bytes);
        }
    }
}

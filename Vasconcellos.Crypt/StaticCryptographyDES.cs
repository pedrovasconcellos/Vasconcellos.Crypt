﻿//The MIT License(MIT)
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
    public class StaticCryptographyDES
    {
        private static string BaseKey { get; set; }

        private static byte[] RGBIV { get; set; }

        private static byte[] Salt { get; set; }

        private static byte[] Key { get; set; }

        public static bool Initialized { get; private set; }

        /// <summary>
        /// Initializer [Static Cryptography DES]
        /// Note: If you initialize the class [StaticCryptography] using values generates automatically, store the randomly generated values in some safe place.
        /// Note: To increase the security of encryption, create your own RGBIV and Salt using the automatic class generation methods [Static Cryptography].
        /// </summary>
        /// <param name="rgbiv"></param>
        /// <param name="salt"></param>
        /// <param name="baseKey">Encryption Key</param>
        /// <returns>true</returns>
        public static bool Initialize(string baseKey, byte[] rgbiv = null, byte[] salt = null)
        {
            if (Initialized) throw new Exception("The class [StaticCryptography] can not be initialized more than once.");
            if (rgbiv != null && rgbiv.Length != 8) throw new ArgumentException("The RGBIV must contain 8 positions.");
            if (salt != null && salt.Length != 8) throw new ArgumentException("The Salt must contain 8 positions.");

            if (string.IsNullOrEmpty(baseKey)) throw new ArgumentException("The Basekey can not null or empty.");
            if (baseKey.Length < 8) throw new ArgumentException("Basekey must contain 8 or more positions.");
            if (!baseKey.Any(c => char.IsDigit(c))) throw new ArgumentException("The Basekey must contain at least one digit.");
            if (!baseKey.Any(c => char.IsUpper(c))) throw new ArgumentException("The Basekey must contain at least one upperrcase letter.");
            if (!baseKey.Any(c => char.IsLower(c))) throw new ArgumentException("The Basekey must contain at least one lowercase letter.");

            RGBIV = (rgbiv ?? (new byte[8] { 171, 182, 193, 144, 165, 157, 148, 199 }));
            Salt = (salt ?? (new byte[8] { 0x12, 0x23, 0x45, 0x56, 0x78, 0xff, 0xab, 0x89 }));
            BaseKey = baseKey;
            Key = GenerateKey();

            return Initialized = !(RGBIV == null && Salt == null && string.IsNullOrEmpty(BaseKey) && Key == null);
        }

        private static byte[] GenerateKey()
        {
            using (var keyBytes = new Rfc2898DeriveBytes(BaseKey, Salt))
            {
                return keyBytes.GetBytes(8);
            }
        }

        public static string Encrypt(string text)
        {
            try
            {
                if (string.IsNullOrEmpty(text)) return null;
                if (Initialized == false) throw new ArgumentException($"The class {nameof(StaticCryptographyDES)} was not initialized.");
                using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
                {
                    byte[] inputByteArray = Encoding.UTF8.GetBytes(text);
                    var ms = new MemoryStream();
                    var cs = new CryptoStream(ms, des.CreateEncryptor(Key, RGBIV), CryptoStreamMode.Write);
                    cs.Write(inputByteArray, 0, inputByteArray.Length);
                    cs.FlushFinalBlock();
                    return Convert.ToBase64String(ms.ToArray());
                }
            }
            catch (Exception e)
            {
                throw new Exception(e.Message);
            }
        }

        public static string Decrypt(string text)
        {
            try
            {
                if (string.IsNullOrEmpty(text)) return null;
                if (Initialized == false) throw new ArgumentException($"The class {nameof(StaticCryptographyDES)} was not initialized.");
                using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
                {
                    byte[] inputByteArray = Convert.FromBase64String(text);
                    var ms = new MemoryStream();
                    var cs = new CryptoStream(ms, des.CreateDecryptor(Key, RGBIV), CryptoStreamMode.Write);
                    cs.Write(inputByteArray, 0, inputByteArray.Length);
                    cs.FlushFinalBlock();
                    return Encoding.UTF8.GetString(ms.ToArray());
                }
            }
            catch (Exception e)
            {
                throw new Exception(e.Message);
            }
        }

        public static byte[] GenerateSalt()
        {
            var bytes = new byte[8];
            using (var rngCsp = new RNGCryptoServiceProvider())
            {
                rngCsp.GetBytes(bytes);
            }
            return bytes;
        }

        public static byte[] GenerateRGBIV()
        {
            using (var des = new DESCryptoServiceProvider())
            {
                des.GenerateIV();
                return des.IV;
            }
        }

        public static string GenerateBaseKey()
        {
            var bytes = new byte[77];
            using (var crypto = new RNGCryptoServiceProvider())
            {
                crypto.GetBytes(bytes);
            }          
            return Convert.ToBase64String(bytes);
        }
    }
}

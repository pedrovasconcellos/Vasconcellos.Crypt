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
using System.Security.Cryptography;
using Vasconcellos.Crypt;

namespace CryptTestConsole
{
    internal class Program
    {
        delegate void Func(Obj obj);

        internal static void Main(string[] args)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("\nTo use Asymmetric Cryptography? y = yes\n");
            Console.ForegroundColor = ConsoleColor.White;

            string asymmetric = Console.ReadLine();

            if (asymmetric.Equals("y", StringComparison.OrdinalIgnoreCase)) Asymmetric();
            else Symetric();
        }

        private static void Symetric()
        {
            while (true)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("\nType (1 = StaticDES or 2 = DES or 3 = AES) to use the static encryption class or type anything to use the instantiated crypto class.");
                Console.ForegroundColor = ConsoleColor.White;

                string method = Console.ReadLine();
                if (string.IsNullOrEmpty(method)) return;

                Console.BackgroundColor = ConsoleColor.Magenta;
                Console.WriteLine("Enter the phrase you want to encrypt.\n");
                Console.BackgroundColor = ConsoleColor.Black;

                Func FuncCrypt = GetMethod(Convert.ToInt16(method));
                var text = Console.ReadLine();
                if (string.IsNullOrEmpty(text)) return;
                var obj = new Obj(text);
                FuncCrypt(obj);

                Console.BackgroundColor = ConsoleColor.DarkGreen;
                Console.WriteLine($"\n{obj.EncryptedWord}");
                Console.BackgroundColor = ConsoleColor.Black;
                Console.WriteLine($"\n{obj.DecryptedWord}\n");
                Console.ReadKey();
            }
        }

        private static void Asymmetric()
        {
            while (true)
            {
                var cryptoServiceProvider = new RSACryptoServiceProvider((int)CryptographyRSA.BitsEnum.bit2048);
                var privateKey = cryptoServiceProvider.ExportParameters(true);
                var publicKey = cryptoServiceProvider.ExportParameters(false);

                CryptographyRSA rs = new CryptographyRSA(privateKey, publicKey);

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"\nPublic Key: \n {rs.PublicKeyXML()}\n");
                Console.ForegroundColor = ConsoleColor.White;

                Console.BackgroundColor = ConsoleColor.Magenta;
                Console.WriteLine("Enter the text for Encrypt.");
                Console.BackgroundColor = ConsoleColor.Black;

                //var bytes = new byte[27];
                //using (var crypto = new RNGCryptoServiceProvider())
                //{
                //    crypto.GetBytes(bytes);
                //}
                //var text = Convert.ToBase64String(bytes);

                var text = Console.ReadLine();
                if (string.IsNullOrEmpty(text)) return;
                string cypher = String.Empty;
                if (text != String.Empty)
                {
                    cypher = rs.Encrypt(text);
                    Console.WriteLine($"\nEncrypted Text:\n\n {cypher} \n");

                }

                Console.BackgroundColor = ConsoleColor.Magenta;
                Console.WriteLine("Press enter to Decrypt.");
                Console.BackgroundColor = ConsoleColor.Black;
                Console.ReadLine();
                var plainText = rs.Decrypt(cypher);
                Console.WriteLine("Text Decrypted:\n");
                Console.WriteLine(plainText);
                Console.ReadLine();
                Console.ReadKey();
            }
        }

        private static Func GetMethod(short method)
        {
            if (method == 1) return new Func(StaticCryptDESTest);
            if (method == 2) return new Func(CryptDESTest);
            if (method == 3) return new Func(CryptAESTest);
            throw new Exception("No method was chosen!");
        }

        private static void StaticCryptDESTest(Obj obj)
        {
            StaticCryptographyDES.Initialize(

                    baseKey: StaticCryptographyDES.GenerateBaseKey(),
                    rgbiv: StaticCryptographyDES.GenerateRGBIV(),
                    salt: StaticCryptographyDES.GenerateSalt()
                );

            obj.EncryptedWord = StaticCryptographyDES.Encrypt(obj.Word);
            obj.DecryptedWord = StaticCryptographyDES.Decrypt(obj.EncryptedWord);
        }

        private static void CryptDESTest(Obj obj)
        {
            var crypt = new CryptographyDES(

                    baseKey: CryptographyDES.GenerateBaseKey(),
                    rgbiv: CryptographyDES.GenerateRGBIV(),
                    salt: CryptographyDES.GenerateSalt()
                );

            obj.EncryptedWord = crypt.Encrypt(obj.Word);
            obj.DecryptedWord = crypt.Decrypt(obj.EncryptedWord);
        }

        private static void CryptAESTest(Obj obj)
        {
            var crypt = new CryptographyAES(

                    key: CryptographyAES.GenerateKey(),
                    iv: CryptographyAES.GenerateIV(),
                    bits: CryptographyAES.BitsEnum.bit256
                );

            obj.EncryptedWord = crypt.Encrypt(obj.Word);
            obj.DecryptedWord = crypt.Decrypt(obj.EncryptedWord);
        }

        private class Obj
        {
            public Obj(string word)
            {
                this.Word = word;
            }

            public string Word { get; set; }
            public string EncryptedWord { get; set; }
            public string DecryptedWord { get; set; }
        }
    }
}

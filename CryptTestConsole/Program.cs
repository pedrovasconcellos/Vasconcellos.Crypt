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
using Vasconcellos.Crypt;

namespace CryptTestConsole
{
    internal class Program
    {
        delegate void Func(Obj obj);

        internal static void Main(string[] args)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("\nType y to use the static encryption class or type anything to use the instantiated crypto class.");
            Console.ForegroundColor = ConsoleColor.White;

            bool useStatic = Console.ReadLine().Equals("y", StringComparison.OrdinalIgnoreCase);

            Console.BackgroundColor = ConsoleColor.Magenta;
            Console.WriteLine("Enter the phrase you want to encrypt.");
            Console.BackgroundColor = ConsoleColor.Black;

            var obj = new Obj(Console.ReadLine());
            Func FuncCrypt = (useStatic ? new Func(StaticCryptTest) : new Func(CryptTest));
            FuncCrypt(obj);

            Console.BackgroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine(obj.EncryptedWord);
            Console.BackgroundColor = ConsoleColor.Black;
            Console.WriteLine(obj.DecryptedWord);

            Console.ReadKey();
        }

        private static void CryptTest(Obj obj)
        {
            var crypt = new Cryptography(

                    baseKey: StaticCryptography.GenerateBaseKey(),
                    rgbiv: StaticCryptography.GenerateRGBIV(),
                    salt: StaticCryptography.GenerateSalt()
                );

            obj.EncryptedWord = crypt.Encrypt(obj.Word);
            obj.DecryptedWord = crypt.Decrypt(obj.EncryptedWord);
        }

        private static void StaticCryptTest(Obj obj)
        {
            StaticCryptography.Initialize(

                    baseKey: StaticCryptography.GenerateBaseKey(),
                    rgbiv: StaticCryptography.GenerateRGBIV(),
                    salt: StaticCryptography.GenerateSalt()
                );

            obj.EncryptedWord = StaticCryptography.Encrypt(obj.Word);
            obj.DecryptedWord = StaticCryptography.Decrypt(obj.EncryptedWord);
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

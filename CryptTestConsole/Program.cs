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
    class Program
    {
        static void Main(string[] args)
        {
            StaticCryptography.Initialize(
                rgbiv: StaticCryptography.GenerateRGBIV(),
                salt: StaticCryptography.GenerateSalt(),
                baseKey: StaticCryptography.GenerateBaseKey()
                );

            Console.BackgroundColor = ConsoleColor.Magenta;
            Console.WriteLine("Enter the phrase you want to encrypt.");
            Console.BackgroundColor = ConsoleColor.Black;

            string word = Console.ReadLine();
            string encrypt = Vasconcellos.Crypt.StaticCryptography.Encrypt(word);

            Console.BackgroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine(encrypt);
            Console.BackgroundColor = ConsoleColor.Black;

            Console.WriteLine(Vasconcellos.Crypt.StaticCryptography.Decrypt(encrypt));
            Console.ReadKey();
        }
    }
}

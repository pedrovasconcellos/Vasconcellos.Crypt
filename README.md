# Vasconcellos.Crypt

### License: MIT License 
### Copyright (c) 2018 Pedro Vasconcellos

#### Author: Pedro Henrique Vasconcellos
#### Creation Date: 28/12/2018

#### Description: Encryption developed in .NET Standard

#### Site: https://vasconcellos.solutions

#### Nuget: https://www.nuget.org/packages/Vasconcellos.Crypt/

##### Nuget Package Manager: Install-Package Vasconcellos.Crypt
##### Nuget .NET CLI: dotnet add package Vasconcellos.Crypt


Use to initialize the static cryptography
```csharp
using Vasconcellos.Crypt;
class Program
{
    static void YourMethod(string[] args)
    {
        // Note:
        ///If you initialize the class [StaticCryptography] using values generates automatically, 
        //store the randomly generated values in some safe place.
        
        StaticCryptography.Initialize(
            baseKey: StaticCryptography.GenerateBaseKey(),
            rgbiv: StaticCryptography.GenerateRGBIV(),
            salt: StaticCryptography.GenerateSalt()
            );
    }
}
```

Example of how to encrypt
```csharp
public string YourMethod(string word)
{
    return Vasconcellos.Crypt.StaticCryptography.Encrypt(word);
}
```

Example of how to decrypt
```csharp
public string YourMethod(string word)
{
    return Vasconcellos.Crypt.StaticCryptography.Decrypt(word);
}
```
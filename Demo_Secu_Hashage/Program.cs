using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System;
using System.Security.Cryptography;

namespace Demo_Secu_Hashage
{
   class Program
   {
      static void Main(string[] args)
      {
         // Mdp recu à hashé avant le stockage en DB
         Console.Write("Veuillez entrer le mot de passe à hashé : ");
         string mdp = Console.ReadLine();

         // Génération d'un salt pour amélioré le hashage
         byte[] salt = GenerateSalt();
         Console.WriteLine($"Salt: {Convert.ToBase64String(salt)}");

         // Hashage du mot de passe
         byte[] hash = GenerateHash(mdp, salt);
         Console.WriteLine($"Hash: {Convert.ToBase64String(hash)}");

         // Mdp recu à hashé avant le stockage en DB
         Console.Write("Veuillez entrer de nouveau le mot de passe : ");
         string mdpCheck = Console.ReadLine();

         // Vérifier le mot de passe entrer et celui qui a été hashé
         bool check = Verify(mdpCheck, hash, salt);
         Console.WriteLine("Validation : " + (check ? "OK" : "BOUM"));
      }

      private static byte[] GenerateSalt()
      {
         // Génération d'un tableau de 16 byte (128-bit)
         byte[] salt = new byte[16];
         using(RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
         {
            rng.GetNonZeroBytes(salt);
         }
         return salt;
      }

      private static byte[] GenerateHash(string password, byte[] salt)
      {
         // Nugget package : Microsoft.AspNetCore.Cryptography.KeyDerivation
         byte[] hash = KeyDerivation.Pbkdf2(
            password,
            salt,
            KeyDerivationPrf.HMACSHA512,
            1000,
            64 // 512-bit
         );
         return hash;
      }

      private static bool Verify(string password, byte[] passwordHash, byte[] salt)
      {
         byte[] checkHash = GenerateHash(password, salt);

         return Convert.ToBase64String(passwordHash) 
                  == Convert.ToBase64String(checkHash);
      }
   }
}

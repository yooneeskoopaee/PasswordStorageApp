using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace PasswordStorageApp
{
    class Program
    {
        private const int iterations  = 210000;
        private const int saltSize = 16;
        private const int hashSize = 32;

        static void Main(string[] args)
        {
            Console.WriteLine("Enter username:");
            var username = Console.ReadLine();
        
            if(string.IsNullOrWhiteSpace(username))
            {
                Console.WriteLine("username cannot be empty");
                return;
            }

            Console.WriteLine("Enter password:");
            var password = Console.ReadLine();

            if(string.IsNullOrWhiteSpace(password))
            {
                Console.WriteLine("password cannot be empty");
                return;
            }

            SaveCredentials(username, password);
            Console.WriteLine("Credentials saved securly.");
        }

        static void SaveCredentials(string username, string password)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(saltSize);

            byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
                password:password,
                salt: salt,
                iterations: iterations,
                hashAlgorithm: HashAlgorithmName.SHA256,
                outputLength: hashSize                               
                );

            var encodeUsername = Convert.ToBase64String(Encoding.UTF8.GetBytes(username));
            var encodeSalt = Convert.ToBase64String(salt);
            var encodeHash = Convert.ToBase64String(hash);

            var line = $"{encodeUsername}:{iterations}:{encodeSalt}:{encodeHash}";
            File.AppendAllText("users.txt", line + Environment.NewLine);
        }

        static bool VerifyPassword(string password, byte[] salt, byte[] expectedHash, int iterations)
        {
            byte[] actualHash = Rfc2898DeriveBytes.Pbkdf2(
                password: password,
                salt: salt,
                iterations: iterations,
                hashAlgorithm: HashAlgorithmName.SHA256,
                outputLength: expectedHash.Length
            );

            return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
        }

        static string ReadPassword()
        {
            var password = new StringBuilder();

            while (true)
            {
                var key = Console.ReadKey(intercept: true);

                if (key.Key == ConsoleKey.Enter)
                    break;

                if (key.Key == ConsoleKey.Backspace)
                {
                    if (password.Length > 0)
                    {
                        password.Length--;
                        Console.Write("\b \b");
                    }

                    continue;
                }

                password.Append(key.KeyChar);
                Console.Write("*");
            }

            return password.ToString();
        }
    }
}
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.IO.Compression;

namespace FileEncryptor
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Title = "DMep";
            while (true)
            {
                Console.WriteLine("Choose mode: (E)ncrypt, (D)ecrypt, or (Q)uit");
                char mode = Console.ReadKey().KeyChar;
                Console.WriteLine();

                if (mode == 'E' || mode == 'e')
                {
                    EncryptFile();
                }
                else if (mode == 'D' || mode == 'd')
                {
                    DecryptFile();
                }
                else if (mode == 'Q' || mode == 'q')
                {
                    break;
                }
                else
                {
                    Console.WriteLine("Invalid mode selected.");
                }
            }
        }

        private static void EncryptFile()
        {
            Console.Write("Enter the path of the file to encrypt: ");
            string filePath = Console.ReadLine().Trim('"');

            Console.Write("Enter the encryption password: ");
            string password = Console.ReadLine();

            Console.Write("Enter the desired name of the file: ");
            string fileName = Console.ReadLine();
            string destFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, fileName + ".dmef");

            try
            {
                byte[] key = CreateKey(password);
                byte[] iv = CreateIV();
                string fileExtension = Path.GetExtension(filePath);

                using (FileStream fsInput = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                using (FileStream fsOutput = new FileStream(destFilePath, FileMode.Create, FileAccess.Write))
                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;

                    fsOutput.Write(iv, 0, iv.Length);

                    byte[] fileNameBytes = Encoding.UTF8.GetBytes(fileName);
                    fsOutput.Write(BitConverter.GetBytes(fileNameBytes.Length), 0, sizeof(int));
                    fsOutput.Write(fileNameBytes, 0, fileNameBytes.Length);

                    byte[] fileExtensionBytes = Encoding.UTF8.GetBytes(fileExtension);
                    fsOutput.Write(BitConverter.GetBytes(fileExtensionBytes.Length), 0, sizeof(int));
                    fsOutput.Write(fileExtensionBytes, 0, fileExtensionBytes.Length);

                    using (CryptoStream cs = new CryptoStream(fsOutput, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    using (GZipStream gzs = new GZipStream(cs, CompressionMode.Compress))
                    {
                        fsInput.CopyTo(gzs);
                    }
                }

                Console.WriteLine($"File successfully encrypted to {destFilePath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred during encryption: " + ex.Message);
            }
        }

        private static void DecryptFile()
        {
            Console.Write("Enter the path of the file to decrypt: ");
            string filePath = Console.ReadLine().Trim('"');

            Console.Write("Enter the decryption password: ");
            string password = Console.ReadLine();

            try
            {
                byte[] key = CreateKey(password);

                using (FileStream fsInput = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                {
                    byte[] iv = new byte[16];
                    fsInput.Read(iv, 0, iv.Length);

                    byte[] lengthBuffer = new byte[sizeof(int)];
                    fsInput.Read(lengthBuffer, 0, lengthBuffer.Length);
                    int fileNameLength = BitConverter.ToInt32(lengthBuffer, 0);

                    byte[] fileNameBytes = new byte[fileNameLength];
                    fsInput.Read(fileNameBytes, 0, fileNameBytes.Length);
                    string originalFileName = Encoding.UTF8.GetString(fileNameBytes);

                    fsInput.Read(lengthBuffer, 0, lengthBuffer.Length);
                    int fileExtensionLength = BitConverter.ToInt32(lengthBuffer, 0);

                    byte[] fileExtensionBytes = new byte[fileExtensionLength];
                    fsInput.Read(fileExtensionBytes, 0, fileExtensionBytes.Length);
                    string fileExtension = Encoding.UTF8.GetString(fileExtensionBytes);

                    string destFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, originalFileName + fileExtension);

                    using (FileStream fsOutput = new FileStream(destFilePath, FileMode.Create, FileAccess.Write))
                    using (Aes aes = Aes.Create())
                    {
                        aes.Key = key;
                        aes.IV = iv;

                        using (CryptoStream cs = new CryptoStream(fsInput, aes.CreateDecryptor(), CryptoStreamMode.Read))
                        using (GZipStream gzs = new GZipStream(cs, CompressionMode.Decompress))
                        {
                            gzs.CopyTo(fsOutput);
                        }
                    }

                    Console.WriteLine($"File successfully decrypted to {destFilePath}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred during decryption: " + ex.Message);
            }
        }

        private static byte[] CreateKey(string password)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
            }
        }

        private static byte[] CreateIV()
        {
            using (Aes aes = Aes.Create())
            {
                aes.GenerateIV();
                return aes.IV;
            }
        }
    }
}

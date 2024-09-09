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
                char mode = Console.ReadKey(true).KeyChar; // The `true` argument hides the character input
                Console.WriteLine(); // This ensures the input is not displayed

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

            Console.Write("Enter the desired name of the encrypted file (without extension): ");
            string encryptedFileName = Console.ReadLine();
            string destFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, encryptedFileName + ".dmef");

            Console.Write("Do you want to compress the file before encryption? (Y/N): ");
            bool compress = Console.ReadKey().KeyChar.ToString().ToLower() == "y";
            Console.WriteLine();

            try
            {
                byte[] key = CreateKey(password);
                byte[] iv = CreateIV();
                string fileExtension = Path.GetExtension(filePath);
                string originalFileName = Path.GetFileName(filePath); // Get the original filename

                using (FileStream fsInput = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                using (FileStream fsOutput = new FileStream(destFilePath, FileMode.Create, FileAccess.Write))
                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;

                    fsOutput.Write(iv, 0, iv.Length);

                    // Store the original filename
                    byte[] originalFileNameBytes = Encoding.UTF8.GetBytes(originalFileName);
                    fsOutput.Write(BitConverter.GetBytes(originalFileNameBytes.Length), 0, sizeof(int));
                    fsOutput.Write(originalFileNameBytes, 0, originalFileNameBytes.Length);

                    byte[] fileExtensionBytes = Encoding.UTF8.GetBytes(fileExtension);
                    fsOutput.Write(BitConverter.GetBytes(fileExtensionBytes.Length), 0, sizeof(int));
                    fsOutput.Write(fileExtensionBytes, 0, fileExtensionBytes.Length);

                    fsOutput.WriteByte((byte)(compress ? 1 : 0)); // Write the compression flag

                    using (CryptoStream cs = new CryptoStream(fsOutput, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        if (compress)
                        {
                            using (GZipStream gzs = new GZipStream(cs, CompressionMode.Compress))
                            {
                                fsInput.CopyTo(gzs);
                            }
                        }
                        else
                        {
                            fsInput.CopyTo(cs);
                        }
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

                    // Read the original filename length and value
                    byte[] lengthBuffer = new byte[sizeof(int)];
                    fsInput.Read(lengthBuffer, 0, lengthBuffer.Length);
                    int originalFileNameLength = BitConverter.ToInt32(lengthBuffer, 0);

                    byte[] originalFileNameBytes = new byte[originalFileNameLength];
                    fsInput.Read(originalFileNameBytes, 0, originalFileNameBytes.Length);
                    string originalFileName = Encoding.UTF8.GetString(originalFileNameBytes);

                    fsInput.Read(lengthBuffer, 0, lengthBuffer.Length);
                    int fileExtensionLength = BitConverter.ToInt32(lengthBuffer, 0);

                    byte[] fileExtensionBytes = new byte[fileExtensionLength];
                    fsInput.Read(fileExtensionBytes, 0, fileExtensionBytes.Length);
                    string fileExtension = Encoding.UTF8.GetString(fileExtensionBytes);

                    bool compress = fsInput.ReadByte() == 1; // Read the compression flag

                    // Use the original filename with its extension
                    string destFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, originalFileName);

                    using (FileStream fsOutput = new FileStream(destFilePath, FileMode.Create, FileAccess.Write))
                    using (Aes aes = Aes.Create())
                    {
                        aes.Key = key;
                        aes.IV = iv;

                        using (CryptoStream cs = new CryptoStream(fsInput, aes.CreateDecryptor(), CryptoStreamMode.Read))
                        {
                            if (compress)
                            {
                                using (GZipStream gzs = new GZipStream(cs, CompressionMode.Decompress))
                                {
                                    gzs.CopyTo(fsOutput);
                                }
                            }
                            else
                            {
                                cs.CopyTo(fsOutput);
                            }
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

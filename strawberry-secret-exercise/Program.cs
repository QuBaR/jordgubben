using System.Buffers.Binary;
using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;

// Load configuration
var config = new ConfigurationBuilder()
	.SetBasePath(AppContext.BaseDirectory)
	.AddJsonFile("appsettings.json", optional: false)
	.Build();

var encSection = config.GetSection("Encryption");
var iterations = encSection.GetValue<int>("Iterations");
var saltSize = encSection.GetValue<int>("SaltSizeBytes");
var nonceSize = encSection.GetValue<int>("NonceSizeBytes");
var passwordFile = encSection.GetValue<string>("PasswordFile") ?? "password.b64";
var ciphertextFile = encSection.GetValue<string>("CipherTextFile") ?? "secret.bin";

Console.WriteLine("=== Strawberry Secret Encryptor ===");
Console.Write("Enter message to encrypt: ");
var message = Console.ReadLine() ?? string.Empty;

string password = ReadPassword("Enter password (will be stored encoded): ");
if (string.IsNullOrWhiteSpace(password))
{
	Console.WriteLine("Password cannot be empty.");
	return;
}

// Derive key
byte[] salt = RandomNumberGenerator.GetBytes(saltSize);
using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA512);
byte[] key = pbkdf2.GetBytes(32); // 256-bit key

// Encrypt using AES-GCM
byte[] nonce = RandomNumberGenerator.GetBytes(nonceSize);
int tagSize = 16; // bytes (128-bit tag)
using var aesGcm = new AesGcm(key, tagSize);
byte[] plaintext = System.Text.Encoding.UTF8.GetBytes(message);
byte[] ciphertext = new byte[plaintext.Length];
byte[] tag = new byte[tagSize];
aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);

// File format: [magic 4 bytes][version 1 byte][saltLen 1][nonceLen 1][tagLen 1][iterations 4][salt][nonce][tag][ciphertext]
// This allows future extension.
const uint magic = 0x53455243; // 'SERC'
byte version = 1;
if (salt.Length > 255 || nonce.Length > 255 || tag.Length > 255)
{
	Console.WriteLine("Component too large.");
	return;
}
using (var fs = File.Create(Path.Combine(AppContext.BaseDirectory, ciphertextFile)))
{
	Span<byte> header = stackalloc byte[4 + 1 + 3 + 4];
	BinaryPrimitives.WriteUInt32BigEndian(header[..4], magic);
	header[4] = version;
	header[5] = (byte)salt.Length;
	header[6] = (byte)nonce.Length;
	header[7] = (byte)tag.Length;
	BinaryPrimitives.WriteInt32BigEndian(header.Slice(8,4), iterations);
	fs.Write(header);
	fs.Write(salt);
	fs.Write(nonce);
	fs.Write(tag);
	fs.Write(ciphertext);
}

// Store password base64 (Note: storing raw password is insecure in real scenarios!)
var b64Pwd = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(password));
await File.WriteAllTextAsync(Path.Combine(AppContext.BaseDirectory, passwordFile), b64Pwd + Environment.NewLine);

Console.WriteLine($"Encrypted and saved to '{ciphertextFile}'. Password (base64) saved to '{passwordFile}'.");
Console.WriteLine("NOTE: Storing the password is insecure. For demonstration only.");

static string ReadPassword(string prompt)
{
	Console.Write(prompt);
	var pwd = new System.Text.StringBuilder();
	while (true)
	{
		var key = Console.ReadKey(intercept: true);
		if (key.Key == ConsoleKey.Enter) { Console.WriteLine(); break; }
		if (key.Key == ConsoleKey.Backspace)
		{
			if (pwd.Length > 0)
			{
				pwd.Length--;
				Console.Write("\b \b");
			}
			continue;
		}
		if (!char.IsControl(key.KeyChar))
		{
			pwd.Append(key.KeyChar);
			Console.Write('*');
		}
	}
	return pwd.ToString();
}

// Optionally: implement decryption if user wants later.

using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using StrawberrySecret;

public class VaultApp
{
	private static string passwordFile = null!;
	private static string ciphertextFile = null!;
	private static string dataRoot = null!;
	private static string projectRoot = null!;
	private static string dataRootPath = null!;
	private static int defaultIterations;
	private static int defaultSaltSize;
	private static int defaultNonceSize;
	private static string profilesFolderName = "profiles";

	public static void Main()
	{
		// Load configuration
		var config = new ConfigurationBuilder()
			.SetBasePath(AppContext.BaseDirectory)
			.AddJsonFile("appsettings.json", optional: false)
			.Build();

		var encSection = config.GetSection("Encryption");
		defaultIterations = encSection.GetValue<int>("Iterations");
		defaultSaltSize = encSection.GetValue<int>("SaltSizeBytes");
		defaultNonceSize = encSection.GetValue<int>("NonceSizeBytes");
		passwordFile = encSection.GetValue<string>("PasswordFile") ?? "password.b64";
		ciphertextFile = encSection.GetValue<string>("CipherTextFile") ?? "secret.bin";
		dataRoot = encSection.GetValue<string>("DataRoot") ?? "data";

		projectRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", ".."));
		dataRootPath = Path.Combine(projectRoot, dataRoot);
		Directory.CreateDirectory(dataRootPath);

		Console.Write("Enter username: ");
		string? username = Console.ReadLine();
		if (string.IsNullOrWhiteSpace(username)) { Console.WriteLine("Username required"); return; }
		var profilesDir = Path.Combine(projectRoot, profilesFolderName);
		Directory.CreateDirectory(profilesDir);
		var profilePath = Path.Combine(profilesDir, username + ".json");
		UserProfile profile;
		if (File.Exists(profilePath))
		{
			profile = JsonSerializer.Deserialize<UserProfile>(File.ReadAllText(profilePath)) ??
					  UserProfile.CreateDefault(username, defaultIterations, defaultSaltSize, defaultNonceSize, 16);
		}
		else
		{
			profile = UserProfile.CreateDefault(username, defaultIterations, defaultSaltSize, defaultNonceSize, 16);
			File.WriteAllText(profilePath, JsonSerializer.Serialize(profile, new JsonSerializerOptions { WriteIndented = true }));
			Console.WriteLine($"Created new profile for '{username}'.");
		}

		Console.WriteLine("=== Strawberry Secret Vault ===");
		Console.WriteLine("Active user: " + profile.Username);
		Console.WriteLine("1) Encrypt new message");
		Console.WriteLine("2) List + decrypt existing");
		Console.WriteLine("3) Show profile info");
		Console.Write("Select option (1/2/3): ");
		var option = Console.ReadLine();

		switch (option)
		{
			case "1":
				EncryptFlow(profile);
				break;
			case "2":
				DecryptFlow(profile);
				break;
			case "3":
				ShowProfile(profile);
				break;
			default:
				Console.WriteLine("Unknown option.");
				break;
		}
	}

	private static void EncryptFlow(UserProfile profile)
	{
		var timestampFolder = DateTime.UtcNow.ToString("yyyyMMdd_HHmmssfff");
		var outputDir = Path.Combine(dataRootPath, timestampFolder);
		Directory.CreateDirectory(outputDir);

		Console.Write("Enter message to encrypt: ");
		var message = Console.ReadLine() ?? string.Empty;
		string password = ReadPassword("Enter password (will be stored encoded): ");
		if (string.IsNullOrWhiteSpace(password)) { Console.WriteLine("Password cannot be empty."); return; }

		// Combine per-user static salt with per-message random salt for domain separation
		byte[] randomSalt = RandomNumberGenerator.GetBytes(profile.SaltSizeBytes);
		byte[] salt = new byte[profile.UserSalt.Length + randomSalt.Length];
		Buffer.BlockCopy(profile.UserSalt, 0, salt, 0, profile.UserSalt.Length);
		Buffer.BlockCopy(randomSalt, 0, salt, profile.UserSalt.Length, randomSalt.Length);
		using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, profile.Iterations, HashAlgorithmName.SHA512);
		byte[] key = pbkdf2.GetBytes(32); // 256-bit key

		byte[] nonce = RandomNumberGenerator.GetBytes(profile.NonceSizeBytes);
		int tagSize = profile.TagSizeBytes;
		using var aesGcm = new AesGcm(key, tagSize);
		byte[] plaintext = Encoding.UTF8.GetBytes(message);
		byte[] ciphertext = new byte[plaintext.Length];
		byte[] tag = new byte[tagSize];
		aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);

		const uint magic = 0x53455243; // 'SERC'
		byte version = 1;
		if (salt.Length > 255 || nonce.Length > 255 || tag.Length > 255) { Console.WriteLine("Component too large."); return; }
		var cipherPath = Path.Combine(outputDir, ciphertextFile);
		using (var fs = File.Create(cipherPath))
		{
			Span<byte> header = stackalloc byte[4 + 1 + 3 + 4];
			BinaryPrimitives.WriteUInt32BigEndian(header[..4], magic);
			header[4] = version;
			header[5] = (byte)salt.Length;
			header[6] = (byte)nonce.Length;
			header[7] = (byte)tag.Length;
			BinaryPrimitives.WriteInt32BigEndian(header.Slice(8,4), profile.Iterations);
			fs.Write(header);
			fs.Write(salt);
			fs.Write(nonce);
			fs.Write(tag);
			fs.Write(ciphertext);
		}

		var b64Pwd = Convert.ToBase64String(Encoding.UTF8.GetBytes(password));
		var passwordPath = Path.Combine(outputDir, passwordFile);
		File.WriteAllText(passwordPath, b64Pwd + Environment.NewLine);

		Console.WriteLine($"Encrypted and saved to '{cipherPath}'.");
		Console.WriteLine("NOTE: Storing the password is insecure. For demonstration only.");
	}

	private static void DecryptFlow(UserProfile profile)
	{
		if (!Directory.Exists(dataRootPath)) { Console.WriteLine("No data directory."); return; }
		var folders = Directory.GetDirectories(dataRootPath)
			.OrderBy(d => d)
			.Where(d => File.Exists(Path.Combine(d, ciphertextFile)) && File.Exists(Path.Combine(d, passwordFile)))
			.ToList();

		if (folders.Count == 0) { Console.WriteLine("No encrypted messages found."); return; }
		Console.WriteLine("Available encrypted messages:");
		for (int i = 0; i < folders.Count; i++)
		{
			Console.WriteLine($"[{i+1}] {Path.GetFileName(folders[i])}");
		}
		Console.Write("Select number to decrypt: ");
		var selStr = Console.ReadLine();
		if (!int.TryParse(selStr, out int sel) || sel < 1 || sel > folders.Count) { Console.WriteLine("Invalid selection."); return; }
		var chosen = folders[sel - 1];
		var cipherPath = Path.Combine(chosen, ciphertextFile);
		var passwordPath = Path.Combine(chosen, passwordFile);
		var passwordB64 = File.ReadAllText(passwordPath).Trim();
		string password = Encoding.UTF8.GetString(Convert.FromBase64String(passwordB64));

		try
		{
			string plaintext = Decrypt(cipherPath, password, profile);
			Console.WriteLine("Decrypted message:");
			Console.WriteLine(plaintext);
		}
		catch (Exception ex)
		{
			Console.WriteLine($"Decryption failed: {ex.Message}");
		}
	}

	private static string Decrypt(string filePath, string password, UserProfile profile)
	{
		using var fs = File.OpenRead(filePath);
		Span<byte> header = stackalloc byte[4 + 1 + 3 + 4];
		if (fs.Read(header) != header.Length) throw new InvalidDataException("Header too short");
		uint magic = BinaryPrimitives.ReadUInt32BigEndian(header[..4]);
		if (magic != 0x53455243) throw new InvalidDataException("Bad magic");
		byte version = header[4];
		if (version != 1) throw new InvalidDataException("Unsupported version");
		int saltLen = header[5];
		int nonceLen = header[6];
		int tagLen = header[7];
		int iterations = BinaryPrimitives.ReadInt32BigEndian(header.Slice(8,4));
		byte[] salt = new byte[saltLen]; fs.ReadExactly(salt);
		byte[] nonce = new byte[nonceLen]; fs.ReadExactly(nonce);
		byte[] tag = new byte[tagLen]; fs.ReadExactly(tag);
		byte[] ciphertext = new byte[fs.Length - fs.Position]; fs.ReadExactly(ciphertext);

		using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA512);
		byte[] key = pbkdf2.GetBytes(32);
		using var aesGcm = new AesGcm(key, tagLen);
		byte[] plaintext = new byte[ciphertext.Length];
		aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
		return Encoding.UTF8.GetString(plaintext);
	}

	private static void ShowProfile(UserProfile profile)
	{
		Console.WriteLine("Profile:");
		Console.WriteLine($" Username: {profile.Username}");
		Console.WriteLine($" Iterations: {profile.Iterations}");
		Console.WriteLine($" SaltSizeBytes (per-message random): {profile.SaltSizeBytes}");
		Console.WriteLine($" NonceSizeBytes: {profile.NonceSizeBytes}");
		Console.WriteLine($" TagSizeBytes: {profile.TagSizeBytes}");
		Console.WriteLine($" Algorithm: {profile.Algorithm}");
		Console.WriteLine($" KDF: {profile.Kdf}");
	}

	private static string ReadPassword(string prompt)
	{
		Console.Write(prompt);
		var pwd = new StringBuilder();
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
}

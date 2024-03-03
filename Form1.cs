using System;
using System.Collections.Generic;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.IO;

namespace Project3_Password_Manager {

    public partial class PasswordManager : Form {

        // Note this is only part of a Winforms GUI application and will not work by itself without the Designer.cs file and the rest of the project.

        // When the program is run first it creates an RSA key pair and an AES key. It encrypts the data with the AES and encrypts the AES key with the RSA key. When you get this
        // program it should have 6 files in /bin which are an AES key, AES IV, some AES encrypted login data, an RSA key pair (used by the program), public RSA and private RSA.
        // You can delete these files and try the program from fresh, just remember to click export keys. If you do forget just delete all the .enc files from bin and start again.

        // symmetric (AES) - single shared secret key for encryption and decryption
        // asymmetric (RSA) - public/private key pair for encryption/decryption. Anyone can encrypt, only private key holder can decrypt. Better for small items like keys.

        readonly CspParameters csp = new CspParameters();
        RSACryptoServiceProvider rsa;

        const string encryptedLoginsFile = @"..\encryptedLogins.enc";
        const string rsaEncryptedAesKeyFile = @"..\rsaAesKey.enc";
        const string rsaEncryptedAesIvFile = @"..\rsaAesIv.enc";

        public PasswordManager() {
            InitializeComponent();
        }

        private void PasswordManager_Load(object sender, EventArgs e) { 

            string rsaKeyPairFile = @"..\RsaKeyPair.enc";
            bool rsaPairFound = false;

            // check for RSA public private key pair and make them if they aren't there
            try { 
                if(File.Exists(rsaKeyPairFile)) { 

                    rsaPairFound = true;
                    string rsaKeyPair = File.ReadAllText(rsaKeyPairFile);
                    rsa = new RSACryptoServiceProvider();
                    rsa.FromXmlString(rsaKeyPair);

                } else {

                    csp.KeyContainerName = rsaKeyPairFile;
                    rsa = new RSACryptoServiceProvider(csp) {
                        PersistKeyInCsp = true
                    };
                }
            } catch {
                MessageBox.Show("Something went wrong with the RSA", "RSA problem", MessageBoxButtons.OK);
            }

            // notify the user if the RSA is found or not
            if(!rsaPairFound) { 
                MessageBox.Show("No RSA. This is either the first run or the RSA keys weren't exported. A new pair will be created, but " +
                    "any data from a previous session cannot be decrypted.", "RSA not found", MessageBoxButtons.OK);
            } else {
                MessageBox.Show("RSA found. ", "RSA found", MessageBoxButtons.OK);
            }

            // check for user data which is AES encrypted, if the file is there, get the raw data and decrypt and place in the list
            if(File.Exists(encryptedLoginsFile) & rsaPairFound) { 
                    
                string encryptedWebsite = "";
                string encryptedUsername = "";
                string encryptedPassword = "";

                try { 
                    // open the saved websites, usernames, passwords
                    string rawEncryptedData = File.ReadAllText(encryptedLoginsFile);

                    string[] lines = rawEncryptedData.Split('\n');
                    foreach(string line in lines) {
                        string[] seperated = line.Split(',');
                        if(seperated.Length == 3) { 
                            encryptedWebsite = seperated[0];
                            encryptedUsername = seperated[1];
                            encryptedPassword = seperated[2];
                            WebsiteLogin encryptedLogin = new WebsiteLogin(encryptedWebsite, encryptedUsername, encryptedPassword);
                            Global.encryptedLogins.Add(encryptedLogin);
                        }
                    }

                MessageBox.Show("Previous AES encrypted logins found in /bin.", "Login data found", MessageBoxButtons.OK);
                } catch {
                    MessageBox.Show("Something went wrong with the AES", "AES problem", MessageBoxButtons.OK);
                }
            } else { 
                MessageBox.Show("No AES encrypted logins found in /bin. Will start fresh", "No user data found", MessageBoxButtons.OK);
            }

            Aes AES = Aes.Create();
            AES.Padding = PaddingMode.PKCS7;

            byte[] keyEncrypted;
            byte[] keyDecrypted;
            byte[] ivBytes;
            int lIV;
            byte[] LenIV;
            int ivLength;

            try { 
                // if theres no AES key, make one, RSA encrypt it and save to a file. Otherwise decrypt it from file
                if(!File.Exists(rsaEncryptedAesKeyFile)) {
                    AES.GenerateKey();
                    keyEncrypted = rsa.Encrypt(AES.Key, false);
                    File.WriteAllBytes(rsaEncryptedAesKeyFile, keyEncrypted);
                   
                } else {
                    keyEncrypted = File.ReadAllBytes(rsaEncryptedAesKeyFile);
                    keyDecrypted = rsa.Decrypt(keyEncrypted, false); // 
                    AES.Key = keyDecrypted;

                }

                // if theres no iv, make one and save to file. Otherwise get it from file
                if(!File.Exists(rsaEncryptedAesIvFile)) {
                    AES.GenerateIV();
                    ivBytes = AES.IV;
                    lIV = ivBytes.Length;
                    LenIV = BitConverter.GetBytes(lIV);

                    using (BinaryWriter writer = new BinaryWriter(File.Open(rsaEncryptedAesIvFile, FileMode.Create))) {

                        writer.Write(LenIV);
                        writer.Write(ivBytes);
                    }

                } else {
                    using (BinaryReader reader = new BinaryReader(File.Open(rsaEncryptedAesIvFile, FileMode.Open))) {
                        ivLength = reader.ReadInt32();
                        ivBytes = reader.ReadBytes(ivLength);
                        AES.IV = ivBytes;
                    }
                }
            } catch (Exception ex) {
                MessageBox.Show($"Something went wrong:\n {ex.ToString()}", "Uh-oh", MessageBoxButtons.OK);
            }

            try { 
                foreach(WebsiteLogin encryptedWebsiteLogin in Global.encryptedLogins) {

                    byte[] encryptedWebsite2 = Convert.FromBase64String(encryptedWebsiteLogin.website);
                    byte[] encryptedUsername2 = Convert.FromBase64String(encryptedWebsiteLogin.username);
                    byte[] encryptedPassword2 = Convert.FromBase64String(encryptedWebsiteLogin.password);

                    string decryptedWebsite = DecryptStringAes(encryptedWebsite2, AES.Key, AES.IV);  // throw padding error (again)
                    string decryptedUsername = DecryptStringAes(encryptedUsername2, AES.Key, AES.IV);
                    string decryptedPassword = DecryptStringAes(encryptedPassword2, AES.Key, AES.IV);

                    WebsiteLogin websiteLogin = new WebsiteLogin(decryptedWebsite, decryptedUsername, decryptedPassword);
                    Global.websiteLogins.Add(websiteLogin);
                }
            } catch {
                MessageBox.Show("Error decrypting user data", "Uh-oh", MessageBoxButtons.OK);
            }

            // once decrypted, fill in the listview for the user
            foreach(WebsiteLogin websiteLogin1 in Global.websiteLogins) {

                string[] loginDetails = new string[2] {websiteLogin1.website, websiteLogin1.username}; 
                ListViewItem item = new ListViewItem(loginDetails); 
                passwordsListView.Items.Add(item).SubItems.AddRange(loginDetails);

            }
        }

        public static class Global {

            public static List<WebsiteLogin> websiteLogins = new List<WebsiteLogin>();
            public static List<WebsiteLogin> encryptedLogins = new List<WebsiteLogin>();

        }

        private void addButton_Click(object sender, EventArgs e) {

            string rsaEncryptedAesKeyFile = @"..\rsaAesKey.enc";
            string rsaEncryptedAesIvFile = @"..\rsaAesIv.enc";

            string website = websiteTextBox.Text;
            string username = usernameTextBox.Text;
            string password = passwordTextBox.Text;

            if(website == "" | username == "" | password == "") {
                MessageBox.Show("Hey silly! You gotta put something in those text boxes", "Uh-oh", MessageBoxButtons.OK);
                return;
            }

            byte[] encryptedWebsite;
            byte[] encryptedUsername;
            byte[] encryptedPassword;
            
            string encryptedLoginsFile = @"..\encryptedLogins.enc";


            WebsiteLogin newWebsiteLogin = new WebsiteLogin(website, username, password);
            Global.websiteLogins.Add(newWebsiteLogin);

            string[] websiteAndUsername = new string[2] {website, username};
            ListViewItem item = new ListViewItem(websiteAndUsername);

            passwordsListView.Items.Add(item).SubItems.AddRange(websiteAndUsername);

            using (Aes AES = Aes.Create()) {   

                AES.Padding = PaddingMode.PKCS7;
                
                try { 
                    byte[] keyEncrypted = File.ReadAllBytes(rsaEncryptedAesKeyFile);
                    byte[] keyDecrypted = rsa.Decrypt(keyEncrypted, false); // System.Security.Cryptography.CryptographicException: 'The parameter is incorrect.
                    AES.Key = keyDecrypted;

                    using (BinaryReader reader = new BinaryReader(File.Open(rsaEncryptedAesIvFile, FileMode.Open))) {
                        int ivLength = reader.ReadInt32();
                        byte[] ivBytes = reader.ReadBytes(ivLength);
                        AES.IV = ivBytes;
                    }
                } catch {
                    MessageBox.Show("Something went reading the AES Key or IV files", "Uh-oh", MessageBoxButtons.OK);
                }
                
                encryptedWebsite = EncryptStringAES(website, AES.Key, AES.IV);
                encryptedUsername = EncryptStringAES(username, AES.Key, AES.IV);
                encryptedPassword = EncryptStringAES(password, AES.Key, AES.IV);
            }
            
            string base64Website = Convert.ToBase64String(encryptedWebsite, Base64FormattingOptions.None);
            string base64Username = Convert.ToBase64String(encryptedUsername, Base64FormattingOptions.None);
            string base64Password = Convert.ToBase64String(encryptedPassword, Base64FormattingOptions.None);

            using (StreamWriter streamWriter = new StreamWriter(encryptedLoginsFile, true)) {
                streamWriter.WriteLine(base64Website + "," + base64Username + "," + base64Password);
            }
            MessageBox.Show("Encrypted website name, username and password saved to file in /bin/", "Success", MessageBoxButtons.OK);
            websiteTextBox.Clear();
            usernameTextBox.Clear();
            passwordTextBox.Clear();
        }

        private void passwordsListView_SelectedIndexChanged(object sender, EventArgs e) {

         //   string encryptedKeysFile = @"..\encryptedKey.txt";

            // guard clause to stop it throwing an out of range exception
            if(passwordsListView.SelectedIndices.Count <= 0) { 
                return; 
            } 

            int intSelectedLoginIndex = passwordsListView.SelectedIndices[0];

            Aes AES = Aes.Create();
            AES.Padding = PaddingMode.PKCS7;

            byte[] keyEncrypted;
            byte[] keyDecrypted;

            // if theres no key, make one, RSA encrypt it and save to a file. Otherwise decrypt it from file
            if(!File.Exists(rsaEncryptedAesKeyFile)) {
                AES.GenerateKey();
                keyEncrypted = rsa.Encrypt(AES.Key, false);
                File.WriteAllBytes(rsaEncryptedAesKeyFile, keyEncrypted);
                   
            } else {
                keyEncrypted = File.ReadAllBytes(rsaEncryptedAesKeyFile);
                keyDecrypted = rsa.Decrypt(keyEncrypted, false); // gives error System.Security.Cryptography.CryptographicException: 'The parameter is incorrect.
                AES.Key = keyDecrypted;
            }

            // if theres no iv, make one and save to file. Otherwise get it from file. I thought it would be better to decrypt the passwords only as needed.
            if(!File.Exists(rsaEncryptedAesIvFile)) {
                AES.GenerateIV();
                byte[] ivBytes = AES.IV;
                int lIV = ivBytes.Length;
                byte[] LenIV = BitConverter.GetBytes(lIV);

                using (BinaryWriter writer = new BinaryWriter(File.Open(rsaEncryptedAesIvFile, FileMode.Create))) {

                    writer.Write(LenIV);
                    writer.Write(ivBytes);
                }

            } else {
                using (BinaryReader reader = new BinaryReader(File.Open(rsaEncryptedAesIvFile, FileMode.Open))) {
                    int ivLength = reader.ReadInt32();
                    byte[] ivBytes = reader.ReadBytes(ivLength);
                    AES.IV = ivBytes;
                }
            }

            string encryptedWebsite = "";
            string encryptedUsername = "";
            string encryptedPassword = "";

            try { 

                string[] rawEncryptedData = File.ReadAllLines(encryptedLoginsFile);
                string line = rawEncryptedData[intSelectedLoginIndex];

                string[] seperated = line.Split(',');

                encryptedWebsite = seperated[0];
                encryptedUsername = seperated[1];
                encryptedPassword = seperated[2];

                byte[] encryptedWebsite2 = Convert.FromBase64String(encryptedWebsite);
                byte[] encryptedUsername2 = Convert.FromBase64String(encryptedUsername);
                byte[] encryptedPassword2 = Convert.FromBase64String(encryptedPassword);

                string decryptedWebsite = DecryptStringAes(encryptedWebsite2, AES.Key, AES.IV);
                string decryptedUsername = DecryptStringAes(encryptedUsername2, AES.Key, AES.IV);
                string decryptedPassword = DecryptStringAes(encryptedPassword2, AES.Key, AES.IV);

                Clipboard.SetText(decryptedPassword);

                MessageBox.Show($"Site: {decryptedWebsite}, Username:{decryptedUsername}, Password: {decryptedPassword} copied to clipboard", "", MessageBoxButtons.OK);
            } catch {
                MessageBox.Show("Something went wrong with decryption", "Uh-oh", MessageBoxButtons.OK);
            }
        }

        private void exportKeysButton_Click(object sender, EventArgs e) {
             
            try { 
                string rsaKeyPairFile = @"..\RsaKeyPair.enc";
                string rsaPrivateKeyFile = @"..\RsaPrivateKey.enc";
                string rsaPublicKeyFile = @"..\RsaPublicKey.enc";
            
                // Export RSA Key Pair. This is used by the program
                string rsaKeyPair = rsa.ToXmlString(true);
                File.WriteAllText(rsaKeyPairFile, rsaKeyPair);

                // Export RSA Private Key
                RSAParameters privateKey = rsa.ExportParameters(true);
                string privateKeyXml = rsa.ToXmlString(true);
                File.WriteAllText(rsaPrivateKeyFile, privateKeyXml);

                // Export RSA Public Key
                RSAParameters publicKey = rsa.ExportParameters(false);
                string publicKeyXml = rsa.ToXmlString(false);
                File.WriteAllText(rsaPublicKeyFile, publicKeyXml);

                MessageBox.Show("RSA pair, public and private keys exported! You'll find them in /bin. The program will use them next time or they can be used elsewhere", "Keys exported successfully", MessageBoxButtons.OK);
            } catch {
                MessageBox.Show("Something went wrong while trying to export keys", "Uh-oh", MessageBoxButtons.OK);
            }
        }

        static byte[] EncryptStringAES(string text, byte[] key, byte[] IV) {

            // Check arguments.
            if (text == null || text.Length <= 0)
                throw new ArgumentNullException("text");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            byte[] encrypted;

            using (Aes AES = Aes.Create()) {
                AES.Key = key;
                AES.IV = IV;
                AES.Padding = PaddingMode.PKCS7;

                // Create an encryptor to perform the stream transform
                ICryptoTransform encryptor = AES.CreateEncryptor(AES.Key, AES.IV);
                // Create the streams used for encryption
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(text);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            return encrypted;
        }

        static string DecryptStringAes(byte[] cipherText, byte[] Key, byte[] IV) {

            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes AES = Aes.Create()) {

                AES.Key = Key;
                AES.IV = IV;
                AES.Padding = PaddingMode.PKCS7;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = AES.CreateDecryptor(AES.Key, AES.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText)) {

                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read)) {

                        using (StreamReader srDecrypt = new StreamReader(csDecrypt)) {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }

        public class WebsiteLogin {

            public string website;
            public string username;
            public string password;

            public WebsiteLogin() {
                website = "";
                username = "";
                password = "";
            }

            public WebsiteLogin(string theWebsite, string theUsername, string thePassword) {
                website = theWebsite;
                username = theUsername;
                password = thePassword;
            }

            public string Website {
                get {
                    return website;
                } set {
                    website = value;
                }
            }
        }

        public class NoFileException : Exception {
            public NoFileException ():base() {
                // Thrown if theres no previous AES data in a file. To handle just continue application without prior data
                MessageBox.Show("No AES data found. You are starting from fresh", "No data", MessageBoxButtons.OK);
            }

            public NoFileException (int numOfBadInputs):base() {
            
            }
        }

        private void exitButton_Click(object sender, EventArgs e) {

            DialogResult result = MessageBox.Show("Are you sure you want to exit? If you haven't exported the RSA keys, if you click yes your data will be encrypted forever", "Exit?", MessageBoxButtons.YesNo);
            if (result == DialogResult.Yes) {
                // User clicked yes
                this.Close();
            } else {
                // User clicked no or closed the message box
                return;
            }
        }
    }
}

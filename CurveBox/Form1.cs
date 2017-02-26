using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Security.Cryptography;
using Elliptic;
using System.Diagnostics;

namespace CurveBox
{
    public partial class Form1 : Form
    {
        string dataPath;
        byte[] loadedPrivateKey;
        byte[] loadedPublicKey;
        string saveLocation;
        byte[] loadedPartnerPublicKey;
        bool loadedPartnerKey;
        bool loadedKeychain;
        bool loadedFile;

        public static string Base64Encode(byte[] plainText)
        {
            return System.Convert.ToBase64String(plainText);
        }
        public static byte[] Base64Decode(byte[] base64EncodedData)
        {
            var base64EncodedBytes = System.Convert.FromBase64String(System.Text.Encoding.UTF8.GetString((base64EncodedData)));
            return base64EncodedBytes;
        }

        private void AES_Decrypt(string inputFile, string password)
        {
            //todo:
            // - create error message on wrong password
            // - on cancel: close and delete file
            // - on wrong password: close and delete file!
            // - create a better filen name
            // - could be check md5 hash on the files but it make this slow

            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
            byte[] salt = new byte[32];

            FileStream fsCrypt = new FileStream(inputFile, FileMode.Open);
            fsCrypt.Read(salt, 0, salt.Length);

            RijndaelManaged AES = new RijndaelManaged();
            AES.KeySize = 256;
            AES.BlockSize = 128;
            var key = new Rfc2898DeriveBytes(passwordBytes, salt, 50000);
            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);
            AES.Padding = PaddingMode.PKCS7;
            AES.Mode = CipherMode.CFB;

            CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateDecryptor(), CryptoStreamMode.Read);

            FileStream fsOut = new FileStream(inputFile + ".decrypted", FileMode.Create);

            int read;
            byte[] buffer = new byte[1048576];

            try
            {
                while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
                {
                    Application.DoEvents();
                    fsOut.Write(buffer, 0, read);
                }
            }
            catch (System.Security.Cryptography.CryptographicException ex_CryptographicException)
            {
                Debug.WriteLine("CryptographicException error: " + ex_CryptographicException.Message);
            }
            catch (Exception ex)
            {
                Debug.WriteLine("Error: " + ex.Message);
            }

            try
            {
                cs.Close();
            }
            catch (Exception ex)
            {
                Debug.WriteLine("Error by closing CryptoStream: " + ex.Message);
            }
            finally
            {
                fsOut.Close();
                fsCrypt.Close();
            }
        }
        private void AES_Encrypt(string inputFile, string password)
        {
            //http://stackoverflow.com/questions/27645527/aes-encryption-on-large-files

            //generate random salt
            byte[] salt = GenerateRandomSalt();

            //create output file name
            FileStream fsCrypt = new FileStream(inputFile + ".curvebox", FileMode.Create);

            //convert password string to byte arrray
            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);

            //Set Rijndael symmetric encryption algorithm
            RijndaelManaged AES = new RijndaelManaged();
            AES.KeySize = 256;
            AES.BlockSize = 128;
            AES.Padding = PaddingMode.PKCS7;

            //http://stackoverflow.com/questions/2659214/why-do-i-need-to-use-the-rfc2898derivebytes-class-in-net-instead-of-directly
            //"What it does is repeatedly hash the user password along with the salt." High iteration counts.
            var key = new Rfc2898DeriveBytes(passwordBytes, salt, 50000);
            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);

            //Cipher modes: http://security.stackexchange.com/questions/52665/which-is-the-best-cipher-mode-and-padding-mode-for-aes-encryption
            AES.Mode = CipherMode.CFB;

            //write salt to the begining of the output file, so in this case can be random every time
            fsCrypt.Write(salt, 0, salt.Length);

            CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateEncryptor(), CryptoStreamMode.Write);

            FileStream fsIn = new FileStream(inputFile, FileMode.Open);

            //create a buffer (1mb) so only this amount will allocate in the memory and not the whole file
            byte[] buffer = new byte[1048576];
            int read;

            try
            {
                while ((read = fsIn.Read(buffer, 0, buffer.Length)) > 0)
                {
                    Application.DoEvents(); // -> for responsive GUI, using Task will be better!
                    cs.Write(buffer, 0, read);
                }

                //close up
                fsIn.Close();

            }
            catch (Exception ex)
            {
                Debug.WriteLine("Error: " + ex.Message);
            }
            finally
            {
                cs.Close();
                fsCrypt.Close();
            }
        }
        static byte[] sha256(string password)
        {
            System.Security.Cryptography.SHA256Managed crypt = new System.Security.Cryptography.SHA256Managed();
            System.Text.StringBuilder hash = new System.Text.StringBuilder();
            byte[] crypto = crypt.ComputeHash(Encoding.UTF8.GetBytes(password), 0, Encoding.UTF8.GetByteCount(password));
            foreach (byte theByte in crypto)
            {
                hash.Append(theByte.ToString("x2"));
            }
            return Encoding.UTF8.GetBytes(hash.ToString());
        }

        public static byte[] Combine(byte[] first, byte[] second)
        {
            byte[] ret = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, ret, 0, first.Length);
            Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);
            return ret;
        }

        public static byte[] GenerateRandomSalt()
        {
            //Source: http://www.dotnetperls.com/rngcryptoserviceprovider
            byte[] data = new byte[32];

            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                // Ten iterations.
                for (int i = 0; i < 10; i++)
                {
                    // Fill buffer.
                    rng.GetBytes(data);
                }
            }
            return data;
        }

        public Form1()
        {
            InitializeComponent();
        }

        private void loadKeychain(string location)
        {
            try {
                using (FileStream fsSource = new FileStream(location, FileMode.Open, FileAccess.Read)) {
                    byte[] bytes = new byte[fsSource.Length];
                    int numBytesToRead = (int)fsSource.Length;
                    int numBytesRead = 0;
                    while (numBytesToRead > 0)
                    {
                        // Read may return anything from 0 to numBytesToRead.
                        int n = fsSource.Read(bytes, numBytesRead, numBytesToRead);

                        // Break when the end of the file is reached.
                        if (n == 0)
                            break;

                        numBytesRead += n;
                        numBytesToRead -= n;
                    }
                    numBytesToRead = bytes.Length;
                    Byte[] hash = new Byte[64];
                    Buffer.BlockCopy(bytes, 0, hash, 0, hash.Length);

                    string publicKeyhash = Encoding.UTF8.GetString(hash);
                    byte[] hashBytes = Encoding.UTF8.GetBytes(publicKeyhash);

                    Byte[] fileBytes = new Byte[bytes.Length - 64];
                    Buffer.BlockCopy(bytes, 64, fileBytes, 0, fileBytes.Length);

                    string encodedKey = Encoding.UTF8.GetString(fileBytes);
                    byte[] decodedBytes = Base64Decode(fileBytes);

                    byte[] publicKey = Curve25519.GetPublicKey(decodedBytes);
                    byte[] hashPublic = sha256(System.Text.Encoding.UTF8.GetString(publicKey));

                    if (String.ReferenceEquals(Encoding.UTF8.GetString(hashPublic), publicKeyhash))
                    {
                        MessageBox.Show("Expected pubic key hash does not match calculated hash, loading failed.");
                        return;
                    }

                    loadedPrivateKey = decodedBytes;
                    loadedPublicKey = publicKey;

                    label1.Text = String.Format("Keychain Loaded: YES");
                    label3.Text = String.Format("Loaded path: {0}", location);
                    label2.Text = String.Format("Publickey hash: {0}", publicKeyhash);
                    loadedKeychain = true;
                }
            }
            catch (FileNotFoundException ioEx)
            {
                Console.WriteLine(ioEx.Message);
            }
        }

        private void loadPublicKey(string location)
        {
            try
            {
                using (FileStream fsSource = new FileStream(location, FileMode.Open, FileAccess.Read))
                {
                    byte[] bytes = new byte[fsSource.Length];
                    int numBytesToRead = (int)fsSource.Length;
                    int numBytesRead = 0;
                    while (numBytesToRead > 0)
                    {
                        // Read may return anything from 0 to numBytesToRead.
                        int n = fsSource.Read(bytes, numBytesRead, numBytesToRead);

                        // Break when the end of the file is reached.
                        if (n == 0)
                            break;

                        numBytesRead += n;
                        numBytesToRead -= n;
                    }
                    numBytesToRead = bytes.Length;
                    Byte[] hash = new Byte[64];
                    Buffer.BlockCopy(bytes, 0, hash, 0, hash.Length);

                    string publicKeyhash = Encoding.UTF8.GetString(hash);
                    byte[] hashBytes = Encoding.UTF8.GetBytes(publicKeyhash);

                    Byte[] fileBytes = new Byte[bytes.Length - 64];
                    Buffer.BlockCopy(bytes, 64, fileBytes, 0, fileBytes.Length);

                    string encodedKey = Encoding.UTF8.GetString(fileBytes);
                    byte[] decodedBytes = Base64Decode(fileBytes);

                    byte[] hashPublic = sha256(System.Text.Encoding.UTF8.GetString(decodedBytes));

                    if (String.ReferenceEquals(Encoding.UTF8.GetString(hashPublic), publicKeyhash))
                    {
                        MessageBox.Show("Expected pubic key hash does not match calculated hash, loading failed.");
                        return;
                    }

                    loadedPartnerPublicKey = decodedBytes;

                    label4.Text = String.Format("Loaded partner publickey: YES");
                    label5.Text = String.Format("Partner hash: {0}", publicKeyhash);
                    loadedPartnerKey = true;
                }
            }
            catch (FileNotFoundException ioEx)
            {
                Console.WriteLine(ioEx.Message);
            }
        }

        private void button5_Click(object sender, EventArgs e)
        {
            byte[] aliceRandomBytes = new byte[32];
            RNGCryptoServiceProvider.Create().GetBytes(aliceRandomBytes);

            byte[] alicePrivate = Curve25519.ClampPrivateKey(aliceRandomBytes);
            byte[] alicePublic = Curve25519.GetPublicKey(alicePrivate);

            string base64Key = Base64Encode(alicePrivate);
            byte[] encodedBytes = Encoding.UTF8.GetBytes(base64Key);
            byte[] hashPublic = sha256(System.Text.Encoding.UTF8.GetString(alicePublic));

            SaveFileDialog saveFileDialog1 = new SaveFileDialog();
            saveFileDialog1.Filter = "CurveBox keychain|*.curvechain";
            saveFileDialog1.Title = "Save CurveBox keychain";
            saveFileDialog1.ShowDialog();

            // If the file name is not an empty string open it for saving.  
            if (saveFileDialog1.FileName != "")
            {
                // Saves the Image via a FileStream created by the OpenFile method.  
                System.IO.FileStream fs =
                   (System.IO.FileStream)saveFileDialog1.OpenFile();
                // Saves the Image in the appropriate ImageFormat based upon the  
                // File type selected in the dialog box.  
                // NOTE that the FilterIndex property is one-based.  
                var fw = new BinaryWriter(fs);

                fw.Write(hashPublic);
                fw.Write(encodedBytes);

                fw.Flush();
                fw.Close();
                fs.Close();
            }

            DialogResult dialogResult = MessageBox.Show("Would you like to try to load this new keychain now?", "Load keychain", MessageBoxButtons.YesNo);
            if (dialogResult == DialogResult.Yes)
            {
                loadKeychain(saveFileDialog1.FileName);
            }
            else if (dialogResult == DialogResult.No)
            {
                // do nothing nigga
            }
        }

        private void button6_Click(object sender, EventArgs e)
        {
            OpenFileDialog theDialog = new OpenFileDialog();
            theDialog.Title = "Open CurveBox keychain";
            theDialog.Filter = "CurveBox keychain|*.curvechain";
            if (theDialog.ShowDialog() == DialogResult.OK)
            {
                loadKeychain(theDialog.FileName);
            }
        }

        private void button7_Click(object sender, EventArgs e)
        {
            if (!loadedKeychain)
            {
                MessageBox.Show("Please load or generate a keychain before trying to export the publickey.");
                return;
            }
            string base64Key = Base64Encode(loadedPublicKey);
            byte[] encodedBytes = Encoding.UTF8.GetBytes(base64Key);
            byte[] hashPublic = sha256(System.Text.Encoding.UTF8.GetString(loadedPublicKey));

            SaveFileDialog saveFileDialog1 = new SaveFileDialog();
            saveFileDialog1.Filter = "CurveBox publickey|*.curvepub";
            saveFileDialog1.Title = "Save CurveBox publickey";
            saveFileDialog1.ShowDialog();

            if (saveFileDialog1.FileName != "")
            {
                System.IO.FileStream fs = (System.IO.FileStream)saveFileDialog1.OpenFile();

                var fw = new BinaryWriter(fs);

                fw.Write(hashPublic);
                fw.Write(encodedBytes);

                fw.Flush();
                fw.Close();
                fs.Close();
            }
            MessageBox.Show(String.Format("Saved public key to {0}", saveFileDialog1.FileName));
        }

        private void button8_Click(object sender, EventArgs e)
        {
            OpenFileDialog theDialog = new OpenFileDialog();
            theDialog.Title = "Open CurveBox publickey";
            theDialog.Filter = "CurveBox publickey|*.curvepub";
            if (theDialog.ShowDialog() == DialogResult.OK)
            {
                loadPublicKey(theDialog.FileName);
            }
        }

        private void button3_Click(object sender, EventArgs e)
        {
            
            if (loadedPartnerKey && loadedKeychain)
            {
                OpenFileDialog theDialog = new OpenFileDialog();
                theDialog.Title = "Open Text File";
                theDialog.Filter = "TXT files|*.txt";
                if (theDialog.ShowDialog() == DialogResult.OK)
                {
                    string filename = theDialog.FileName;

                    dataPath = filename;
                    loadedFile = true;
                    //label3.Text = String.Format("Loaded file: {0}", filename);
                }

                if (!loadedFile)
                {
                    MessageBox.Show("No file loaded!");
                    return;
                }

                byte[] sharedKey = Curve25519.GetSharedSecret(loadedPrivateKey, loadedPartnerPublicKey);
                byte[] hashedKey = sha256(System.Text.Encoding.UTF8.GetString(sharedKey));
                AES_Encrypt(dataPath, Encoding.UTF8.GetString(sharedKey));
                MessageBox.Show(String.Format("Wrote encrypted data to {0}", dataPath + ".curvebox"));
            }
            else
            {
                MessageBox.Show("Please load your keychain and your partners public key");
                return;
            }
        }

        private void button4_Click(object sender, EventArgs e)
        {
            if (loadedPartnerKey && loadedKeychain)
            {
                OpenFileDialog theDialog = new OpenFileDialog();
                theDialog.Title = "Open file to decrypt";
                theDialog.Filter = "CurveBox encrypted file |*.curvebox";
                if (theDialog.ShowDialog() == DialogResult.OK)
                {
                    string filename = theDialog.FileName;

                    dataPath = filename;
                    loadedFile = true;
                }

                if (!loadedFile)
                {
                    MessageBox.Show("No file loaded!");
                    return;
                }

                byte[] sharedKey = Curve25519.GetSharedSecret(loadedPrivateKey, loadedPartnerPublicKey);
                byte[] hashedKey = sha256(System.Text.Encoding.UTF8.GetString(sharedKey));
                AES_Decrypt(dataPath, Encoding.UTF8.GetString(sharedKey));
                MessageBox.Show(String.Format("Wrote decrypted data to {0}", dataPath + ".decrypted"));
            }
            else
            {
                MessageBox.Show("Please load your keychain and your partners public key");
                return;
            }
        }
    }
}

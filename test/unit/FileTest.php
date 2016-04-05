<?php

namespace Defuse\Crypto;

class FileTest extends \PHPUnit_Framework_TestCase
{
    private $key;
    private static $FILE_DIR;
    private static $TEMP_DIR;

    public function setUp()
    {
        self::$FILE_DIR = __DIR__ . '/File';
        self::$TEMP_DIR = self::$FILE_DIR . '/tmp';
        if (! is_dir(self::$TEMP_DIR)) {
            mkdir(self::$TEMP_DIR);
        }

        $this->key = File::createNewRandomKey();
    }

    public function tearDown()
    {
        array_map('unlink', glob(self::$TEMP_DIR . '/*'));
        rmdir(self::$TEMP_DIR);
    }

    /**
     * Test encryption from one file name to a destination file name
     *
     * @dataProvider fileToFileProvider
     *
     * @param string $srcName source file name
     */
    public function testFileToFile($srcName)
    {
        $src = self::$FILE_DIR . '/' . $srcName;

        $dest1  = self::$TEMP_DIR . '/ff1';
        $result = File::encryptFile($src, $dest1, $this->key);
        $this->assertTrue($result,
            sprintf('File "%s" did not encrypt successfully.', $src));
        $this->assertFileExists($dest1, 'destination file not created.');

        $reverse1 = self::$TEMP_DIR . '/rv1';
        $result   = File::decryptFile($dest1, $reverse1, $this->key);
        $this->assertTrue($result,
            sprintf('File "%s" did not decrypt successfully.', $dest1));
        $this->assertFileExists($reverse1);
        $this->assertSame(md5_file($src), md5_file($reverse1),
            'File and encrypted-decrypted file do not match.');

        $dest2  = self::$TEMP_DIR . '/ff2';
        $result = File::encryptFile($reverse1, $dest2, $this->key);
        $this->assertFileExists($dest2);
        $this->assertTrue($result,
            sprintf('File "%s" did not re-encrypt successfully.', $reverse1));

        $this->assertNotEquals(md5_file($dest1), md5_file($dest2),
            'First and second encryption produced identical files.');

        $reverse2 = self::$TEMP_DIR . '/rv2';
        $result   = File::decryptFile($dest2, $reverse2, $this->key);
        $this->assertTrue($result,
            sprintf('File "%s" did not re-decrypt successfully.', $dest1));
        $this->assertSame(md5_file($src), md5_file($reverse2),
            'File and encrypted-decrypted file do not match.');
    }

    /**
     * Test encryption from one file name to a destination file name (password).
     *
     * @dataProvider fileToFileProvider
     *
     * @param string $srcName source file name
     */
    public function testFileToFileWithPassword($srcName)
    {
        $src = self::$FILE_DIR . '/' . $srcName;

        $dest1  = self::$TEMP_DIR . '/ff1';
        $result = File::encryptFileWithPassword($src, $dest1, "password");
        $this->assertTrue($result,
            sprintf('File "%s" did not encrypt successfully.', $src));
        $this->assertFileExists($dest1, 'destination file not created.');

        $reverse1 = self::$TEMP_DIR . '/rv1';
        $result   = File::decryptFileWithPassword($dest1, $reverse1, "password");
        $this->assertTrue($result,
            sprintf('File "%s" did not decrypt successfully.', $dest1));
        $this->assertFileExists($reverse1);
        $this->assertSame(md5_file($src), md5_file($reverse1),
            'File and encrypted-decrypted file do not match.');

        $dest2  = self::$TEMP_DIR . '/ff2';
        $result = File::encryptFileWithPassword($reverse1, $dest2, "password");
        $this->assertFileExists($dest2);
        $this->assertTrue($result,
            sprintf('File "%s" did not re-encrypt successfully.', $reverse1));

        $this->assertNotEquals(md5_file($dest1), md5_file($dest2),
            'First and second encryption produced identical files.');

        $reverse2 = self::$TEMP_DIR . '/rv2';
        $result   = File::decryptFileWithPassword($dest2, $reverse2, "password");
        $this->assertTrue($result,
            sprintf('File "%s" did not re-decrypt successfully.', $dest1));
        $this->assertSame(md5_file($src), md5_file($reverse2),
            'File and encrypted-decrypted file do not match.');
    }

    /**
     * @dataProvider fileToFileProvider
     *
     * @param string $src source handle
     */
    public function testResourceToResource($srcFile)
    {
        $srcName  = self::$FILE_DIR . '/' . $srcFile;
        $destName = self::$TEMP_DIR . "/$srcFile.dest";
        $src      = fopen($srcName, 'r');
        $dest     = fopen($destName, 'w');

        $success = File::encryptResource($src, $dest, $this->key);
        $this->assertTrue($success, 'File did not encrypt successfully.');

        fclose($src);
        fclose($dest);

        $src2  = fopen($destName, 'r');
        $dest2 = fopen(self::$TEMP_DIR . '/dest2', 'w');

        $success = File::decryptResource($src2, $dest2, $this->key);
        $this->assertTrue($success, 'File did not decrypt successfully.');
        fclose($src2);
        fclose($dest2);

        $this->assertSame(md5_file($srcName), md5_file(self::$TEMP_DIR . '/dest2'),
            'Original file mismatches the result of encrypt and decrypt');
    }

    /**
     * @dataProvider fileToFileProvider
     *
     * @param string $src source handle
     */
    public function testResourceToResourceWithPassword($srcFile)
    {
        $srcName  = self::$FILE_DIR . '/' . $srcFile;
        $destName = self::$TEMP_DIR . "/$srcFile.dest";
        $src      = fopen($srcName, 'r');
        $dest     = fopen($destName, 'w');

        $success = File::encryptResourceWithPassword($src, $dest, "password");
        $this->assertTrue($success, 'File did not encrypt successfully.');

        fclose($src);
        fclose($dest);

        $src2  = fopen($destName, 'r');
        $dest2 = fopen(self::$TEMP_DIR . '/dest2', 'w');

        $success = File::decryptResourceWithPassword($src2, $dest2, "password");
        $this->assertTrue($success, 'File did not decrypt successfully.');
        fclose($src2);
        fclose($dest2);

        $this->assertSame(md5_file($srcName), md5_file(self::$TEMP_DIR . '/dest2'),
            'Original file mismatches the result of encrypt and decrypt');
    }

    /**
     * @expectedException \Defuse\Crypto\Exception\InvalidCiphertextException
     * @excpectedExceptionMessage Ciphertext file has a bad magic number.
     */
    public function testDecryptBadMagicNumber()
    {
        $junk = self::$TEMP_DIR . '/junk';
        file_put_contents($junk, 'This file does not have the right magic number.');
        File::decryptFile($junk, self::$TEMP_DIR . '/unjunked', $this->key);
    }

    /**
     * @dataProvider garbageCiphertextProvider
     * @expectedException \Defuse\Crypto\Exception\InvalidCiphertextException
     */
    public function testDecryptGarbage($ciphertext)
    {
        $junk = self::$TEMP_DIR . '/junk';
        file_put_contents($junk, $ciphertext);
        File::decryptFile($junk, self::$TEMP_DIR . '/unjunked', $this->key);
    }

    public function garbageCiphertextProvider()
    {
        $ciphertexts = [
            [str_repeat('this is not anything that can be decrypted.', 100)],
        ];
        for ($i = 0; $i < 1024; $i++) {
            $ciphertexts[] = [Core::CURRENT_VERSION . str_repeat('A', $i)];
        }
        return $ciphertexts;
    }

    /**
     * @expectedException \Defuse\Crypto\Exception\InvalidCiphertextException
     */
    public function testDecryptEmptyFile()
    {
        $junk = self::$TEMP_DIR . '/junk';
        file_put_contents($junk, '');
        File::decryptFile($junk, self::$TEMP_DIR . '/unjunked', $this->key);
    }

    /**
     * @expectedException \Defuse\Crypto\Exception\InvalidCiphertextException
     */
    public function testDecryptTruncatedCiphertext()
    {
        // This tests for issue #115 on GitHub.
        $plaintext_path  = self::$TEMP_DIR . '/plaintext';
        $ciphertext_path = self::$TEMP_DIR . '/ciphertext';
        $truncated_path  = self::$TEMP_DIR . '/truncated';

        file_put_contents($plaintext_path, str_repeat('A', 1024));
        File::encryptFile($plaintext_path, $ciphertext_path, $this->key);

        $ciphertext = file_get_contents($ciphertext_path);
        $truncated  = substr($ciphertext, 0, 64);
        file_put_contents($truncated_path, $truncated);

        File::decryptFile($truncated_path, $plaintext_path, $this->key);
    }

    public function testEncryptWithCryptoDecryptWithFile()
    {
        $ciphertext_path = self::$TEMP_DIR . '/ciphertext';
        $plaintext_path  = self::$TEMP_DIR . '/plaintext';

        $key        = Crypto::createNewRandomKey();
        $plaintext  = 'Plaintext!';
        $ciphertext = Crypto::encrypt($plaintext, $key, true);
        file_put_contents($ciphertext_path, $ciphertext);

        File::decryptFile($ciphertext_path, $plaintext_path, $key);

        $plaintext_decrypted = file_get_contents($plaintext_path);
        $this->assertSame($plaintext, $plaintext_decrypted);
    }

    public function testEncryptWithFileDecryptWithCrypto()
    {
        $ciphertext_path = self::$TEMP_DIR . '/ciphertext';
        $plaintext_path  = self::$TEMP_DIR . '/plaintext';

        $key       = Crypto::createNewRandomKey();
        $plaintext = 'Plaintext!';
        file_put_contents($plaintext_path, $plaintext);
        File::encryptFile($plaintext_path, $ciphertext_path, $key);

        $ciphertext          = file_get_contents($ciphertext_path);
        $plaintext_decrypted = Crypto::decrypt($ciphertext, $key, true);
        $this->assertSame($plaintext, $plaintext_decrypted);
    }

    /**
     * @expectedException \Defuse\Crypto\Exception\InvalidCiphertextException
     * @excpectedExceptionMessage Message Authentication failure; tampering detected.
     */
    public function testExtraData()
    {
        $src  = self::$FILE_DIR . '/wat-gigantic-duck.jpg';
        $dest = self::$TEMP_DIR . '/err';

        File::encryptFile($src, $dest, $this->key);

        file_put_contents($dest, str_repeat('A', 2048), FILE_APPEND);

        File::decryptFile($dest, $dest . '.jpg', $this->key);
    }

    public function testFileCreateRandomKey()
    {
        $result = File::createNewRandomKey();
        $this->assertInstanceOf('\Defuse\Crypto\Key', $result);
    }

    public function fileToFileProvider()
    {
        $data = [];

        $data['wat-giagantic-duck'] = ['wat-gigantic-duck.jpg'];
        $data['large']              = ['large.jpg'];
        # Created from /dev/urandom in test.sh
        $data['extra-large'] = ['big-generated-file'];

        return $data;
    }
}

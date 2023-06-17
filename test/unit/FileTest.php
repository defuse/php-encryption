<?php

namespace Defuse\Crypto;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class FileTest extends TestCase
{
    private $key;
    private static $FILE_DIR;
    private static $TEMP_DIR;

    public function set_up()
    {
        self::$FILE_DIR = __DIR__ . '/File';
        self::$TEMP_DIR = self::$FILE_DIR . '/tmp';
        if (! is_dir(self::$TEMP_DIR)) {
            mkdir(self::$TEMP_DIR);
        }

        $this->key = Key::createNewRandomKey();
    }

    public function tear_down()
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
        File::encryptFile($src, $dest1, $this->key);
        $this->assertFileExists($dest1, 'destination file not created.');

        $reverse1 = self::$TEMP_DIR . '/rv1';
        File::decryptFile($dest1, $reverse1, $this->key);
        $this->assertFileExists($reverse1);
        $this->assertSame(md5_file($src), md5_file($reverse1),
            'File and encrypted-decrypted file do not match.');

        $dest2  = self::$TEMP_DIR . '/ff2';
        File::encryptFile($reverse1, $dest2, $this->key);
        $this->assertFileExists($dest2);

        $this->assertNotEquals(md5_file($dest1), md5_file($dest2),
            'First and second encryption produced identical files.');

        $reverse2 = self::$TEMP_DIR . '/rv2';
        File::decryptFile($dest2, $reverse2, $this->key);
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
        File::encryptFileWithPassword($src, $dest1, 'password');
        $this->assertFileExists($dest1, 'destination file not created.');

        $reverse1 = self::$TEMP_DIR . '/rv1';
        File::decryptFileWithPassword($dest1, $reverse1, 'password');
        $this->assertFileExists($reverse1);
        $this->assertSame(md5_file($src), md5_file($reverse1),
            'File and encrypted-decrypted file do not match.');

        $dest2  = self::$TEMP_DIR . '/ff2';
        File::encryptFileWithPassword($reverse1, $dest2, 'password');
        $this->assertFileExists($dest2);

        $this->assertNotEquals(md5_file($dest1), md5_file($dest2),
            'First and second encryption produced identical files.');

        $reverse2 = self::$TEMP_DIR . '/rv2';
        File::decryptFileWithPassword($dest2, $reverse2, 'password');
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

        File::encryptResource($src, $dest, $this->key);

        fclose($src);
        fclose($dest);

        $src2  = fopen($destName, 'r');
        $dest2 = fopen(self::$TEMP_DIR . '/dest2', 'w');

        File::decryptResource($src2, $dest2, $this->key);
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

        File::encryptResourceWithPassword($src, $dest, 'password');

        fclose($src);
        fclose($dest);

        $src2  = fopen($destName, 'r');
        $dest2 = fopen(self::$TEMP_DIR . '/dest2', 'w');

        File::decryptResourceWithPassword($src2, $dest2, 'password');
        fclose($src2);
        fclose($dest2);

        $this->assertSame(md5_file($srcName), md5_file(self::$TEMP_DIR . '/dest2'),
            'Original file mismatches the result of encrypt and decrypt');
    }

    public function testDecryptBadMagicNumber()
    {
        $junk = self::$TEMP_DIR . '/junk';
        file_put_contents($junk, 'This file does not have the right magic number.');
        $this->expectException(\Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException::class);
        $this->expectExceptionMessage('Input file is too small to have been created by this library.');
        File::decryptFile($junk, self::$TEMP_DIR . '/unjunked', $this->key);
    }

    /**
     * @dataProvider garbageCiphertextProvider
     */
    public function testDecryptGarbage($ciphertext)
    {
        $junk = self::$TEMP_DIR . '/junk';
        file_put_contents($junk, $ciphertext);
        $this->expectException(\Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException::class);
        File::decryptFile($junk, self::$TEMP_DIR . '/unjunked', $this->key);
    }

    public static function garbageCiphertextProvider()
    {
        $ciphertexts = [
            [str_repeat('this is not anything that can be decrypted.', 100)],
        ];
        for ($i = 0; $i < 1024; $i++) {
            $ciphertexts[] = [Core::CURRENT_VERSION . str_repeat('A', $i)];
        }
        return $ciphertexts;
    }

    public function testDecryptEmptyFile()
    {
        $junk = self::$TEMP_DIR . '/junk';
        file_put_contents($junk, '');
        $this->expectException(\Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException::class);
        File::decryptFile($junk, self::$TEMP_DIR . '/unjunked', $this->key);
    }

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

        $this->expectException(\Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException::class);
        File::decryptFile($truncated_path, $plaintext_path, $this->key);
    }

    public function testEncryptWithCryptoDecryptWithFile()
    {
        $ciphertext_path = self::$TEMP_DIR . '/ciphertext';
        $plaintext_path  = self::$TEMP_DIR . '/plaintext';

        $key        = Key::createNewRandomKey();
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

        $key       = Key::createNewRandomKey();
        $plaintext = 'Plaintext!';
        file_put_contents($plaintext_path, $plaintext);
        File::encryptFile($plaintext_path, $ciphertext_path, $key);

        $ciphertext          = file_get_contents($ciphertext_path);
        $plaintext_decrypted = Crypto::decrypt($ciphertext, $key, true);
        $this->assertSame($plaintext, $plaintext_decrypted);
    }

    public function testExtraData()
    {
        $src  = self::$FILE_DIR . '/wat-gigantic-duck.jpg';
        $dest = self::$TEMP_DIR . '/err';

        File::encryptFile($src, $dest, $this->key);

        file_put_contents($dest, str_repeat('A', 2048), FILE_APPEND);

        $this->expectException(\Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException::class);
        $this->expectExceptionMessage('Integrity check failed.');
        File::decryptFile($dest, $dest . '.jpg', $this->key);
    }

    public function testFileCreateRandomKey()
    {
        $result = Key::createNewRandomKey();
        $this->assertInstanceOf('\Defuse\Crypto\Key', $result);
    }

    public function testBadSourcePathEncrypt()
    {
        $this->expectException(\Defuse\Crypto\Exception\IOException::class);
        $this->expectExceptionMessage('No such file or directory');
        File::encryptFile('./i-do-not-exist', 'output-file', $this->key);
    }

    public function testBadSourcePathDecrypt()
    {
        $this->expectException(\Defuse\Crypto\Exception\IOException::class);
        $this->expectExceptionMessage('No such file or directory');
        File::decryptFile('./i-do-not-exist', 'output-file', $this->key);
    }

    public function testBadSourcePathEncryptWithPassword()
    {
        $this->expectException(\Defuse\Crypto\Exception\IOException::class);
        $this->expectExceptionMessage('No such file or directory');
        File::encryptFileWithPassword('./i-do-not-exist', 'output-file', 'password');
    }

    public function testBadSourcePathDecryptWithPassword()
    {
        $this->expectException(\Defuse\Crypto\Exception\IOException::class);
        $this->expectExceptionMessage('No such file or directory');
        File::decryptFileWithPassword('./i-do-not-exist', 'output-file', 'password');
    }

    public function testBadDestinationPathEncrypt()
    {
        $src  = self::$FILE_DIR . '/wat-gigantic-duck.jpg';
        $this->expectException(\Defuse\Crypto\Exception\IOException::class);
        $this->expectExceptionMessage('Is a directory');
        File::encryptFile($src, './', $this->key);
    }

    public function testBadDestinationPathDecrypt()
    {
        $src  = self::$FILE_DIR . '/wat-gigantic-duck.jpg';
        $this->expectException(\Defuse\Crypto\Exception\IOException::class);
        $this->expectExceptionMessage('Is a directory');
        File::decryptFile($src, './', $this->key);
    }

    public function testBadDestinationPathEncryptWithPassword()
    {
        $src  = self::$FILE_DIR . '/wat-gigantic-duck.jpg';
        $this->expectException(\Defuse\Crypto\Exception\IOException::class);
        $this->expectExceptionMessage('Is a directory');
        File::encryptFileWithPassword($src, './', 'password');
    }

    public function testBadDestinationPathDecryptWithPassword()
    {
        $src  = self::$FILE_DIR . '/wat-gigantic-duck.jpg';
        $this->expectException(\Defuse\Crypto\Exception\IOException::class);
        $this->expectExceptionMessage('Is a directory');
        File::decryptFileWithPassword($src, './', 'password');
    }

    public function testNonResourceInputEncrypt()
    {
        $resource = fopen('php://memory', 'wb');
        $this->expectException(\Defuse\Crypto\Exception\IOException::class);
        $this->expectExceptionMessage('must be a resource');
        File::encryptResource('not a resource', $resource, $this->key);
        fclose($resource);
    }

    public function testNonResourceOutputEncrypt()
    {
        $resource = fopen('php://memory', 'wb');
        $this->expectException(\Defuse\Crypto\Exception\IOException::class);
        $this->expectExceptionMessage('must be a resource');
        File::encryptResource($resource, 'not a resource', $this->key);
        fclose($resource);
    }

    public function testNonResourceInputDecrypt()
    {
        $resource = fopen('php://memory', 'wb');
        $this->expectException(\Defuse\Crypto\Exception\IOException::class);
        $this->expectExceptionMessage('must be a resource');
        File::decryptResource('not a resource', $resource, $this->key);
        fclose($resource);
    }

    public function testNonResourceOutputDecrypt()
    {
        $resource = fopen('php://memory', 'wb');
        $this->expectException(\Defuse\Crypto\Exception\IOException::class);
        $this->expectExceptionMessage('must be a resource');
        File::decryptResource($resource, 'not a resource', $this->key);
        fclose($resource);
    }

    public function testNonFileResourceDecrypt()
    {
        /* This should behave equivalently to an empty file. Calling fstat() on
            stdin returns a result saying it has zero size. */
        $stdin = fopen('php://stdin', 'r');
        $output = fopen('php://memory', 'wb');
        try {
            File::decryptResource($stdin, $output, $this->key);
        } catch (\Exception $ex) {
            fclose($output);
            fclose($stdin);
            $this->expectException(\Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException::class);
            throw $ex;
        }
    }

    public static function fileToFileProvider()
    {
        $data = [];

        $data['empty-file']         = ['empty-file.txt'];
        $data['wat-giagantic-duck'] = ['wat-gigantic-duck.jpg'];
        # Created from /dev/urandom in test.sh
        $data['extra-large'] = ['big-generated-file'];

        return $data;
    }
}

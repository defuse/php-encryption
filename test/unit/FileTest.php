<?php
/**
 * Created by PhpStorm.
 * User: seth
 * Date: 12/12/15
 * Time: 1:37 AM
 */
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
        if (!is_dir(self::$TEMP_DIR)){
            mkdir(self::$TEMP_DIR);
        }
        
        // See test 'testFileCreateKey'
        $this->key = Key::CreateNewRandomKey();
    }
    
    public function tearDown()
    {
        array_map('unlink', glob(self::$TEMP_DIR . '/*'));
        rmdir(self::$TEMP_DIR);
    }

    /**
     * Test encryption from one file name to a destination file name
     * @dataProvider fileToFileProvider
     * @param string $srcName source file name
     */
    public function testFileToFile($srcName)
    {
        $src = self::$FILE_DIR . '/' . $srcName;
        
        $dest1 = self::$TEMP_DIR . '/ff1';
        $result = File::encryptFile($src, $dest1, $this->key);
        $this->assertTrue($result, 
            sprintf('File "%s" did not encrypt successfully.', $src));
        $this->assertFileExists($dest1, 'destination file not created.');
        
        $reverse1 = self::$TEMP_DIR . '/rv1';
        $result = File::decryptFile($dest1, $reverse1, $this->key);
        $this->assertTrue($result, 
            sprintf('File "%s" did not decrypt successfully.', $dest1));
        $this->assertFileExists($reverse1);
        $this->assertEquals(md5_file($src), md5_file($reverse1), 
            'File and encrypted-decrypted file do not match.');
        
        $dest2 = self::$TEMP_DIR . '/ff2';
        $result = File::encryptFile($reverse1, $dest2, $this->key);
        $this->assertFileExists($dest2);
        $this->assertTrue($result, 
            sprintf('File "%s" did not re-encrypt successfully.', $reverse1));
        
        $this->assertNotEquals(md5_file($dest1), md5_file($dest2), 
            'First and second encryption produced identical files.');

        $reverse2 = self::$TEMP_DIR . '/rv2';
        $result = File::decryptFile($dest2, $reverse2, $this->key);
        $this->assertTrue($result,
            sprintf('File "%s" did not re-decrypt successfully.', $dest1));
        $this->assertEquals(md5_file($src), md5_file($reverse2),
            'File and encrypted-decrypted file do not match.');
        
    }

    /**
     * @dataProvider fileToFileProvider
     * @param string $src source handle
     */
    public function testResourceToResource($srcFile)
    {
        $srcName = self::$FILE_DIR . '/' . $srcFile;
        $destName = self::$TEMP_DIR . "/$srcFile.dest";
        $src = fopen($srcName, 'r');
        $dest = fopen($destName, 'w');
        
        $success = File::encryptResource($src, $dest, $this->key);
        $this->assertTrue($success, "File did not encrypt successfully.");
        
        fclose($src);
        fclose($dest);
        
        $src2 = fopen($destName, 'r');
        $dest2 = fopen(self::$TEMP_DIR . '/dest2', 'w');
        
        $success = File::decryptResource($src2, $dest2, $this->key);
        $this->assertTrue($success, "File did not decrypt successfully.");
        fclose($src2);
        fclose($dest2);
        
        $this->assertEquals(md5_file($srcName), md5_file(self::$TEMP_DIR . '/dest2'),
            'Original file mismatches the result of encrypt and decrypt');
        
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
        $data['large'] = ['large.jpg'];
        
        if (file_exists(__DIR__ . '/File/In_the_Conservatory.jpg')){
            // see File/get_large.sh
            $data['extra-large'] = ['In_the_Conservatory.jpg'];
        }
        
        return $data;
    }
}

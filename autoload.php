<?php
/**
 * PSR-4 compatible autoloader
 */
\spl_autoload_register(function ($class) {
    // Project-specific namespace prefix
    $prefix = 'Defuse\\Crypto\\';

    // Base directory for the namespace prefix
    $base_dir = __DIR__.'/src/';

    // Does the class use the namespace prefix?
    $len = \strlen($prefix);
    if (\strncmp($prefix, $class, $len) !== 0) {
        // no, move to the next registered autoloader
        return;
    }

    // Get the relative class name
    $relative_class = \substr($class, $len);
    
    /**
     * unserialize() -> autoloader -> LFI hardening
     */
    $classmap = array(
        'Config' =>
            'Config.php',
        'Core' =>
            'Core.php',
        'Crypto' =>
            'Crypto.php',
        'Encoding' =>
            'Encoding.php',
        'ExceptionHandler' =>
            'ExceptionHandler.php',
        'File' =>
            'File.php',
        'FileConfig' =>
            'FileConfig.php',
        'Key' =>
            'Key.php',
        'KeyConfig' =>
            'KeyConfig.php',
        'RuntimeTests' =>
            'RuntimeTests.php',
        'StreamInterface' =>
            'StreamInterface.php',
        // Exceptions:
        'Exception\\CannotPerformOperationException' =>
            'Exception/CannotPerformOperationException.php',
        'Exception\\CryptoException' =>
            'Exception/CryptoException.php',
        'Exception\\CryptoTestFailedException' =>
            'Exception/CryptoTestFailedException.php',
        'Exception\\InvalidCiphertextException' =>
            'Exception/InvalidCiphertextException.php',
    );
    foreach ($classmap as $classname => $file) {
        if ($classname === $relative_class) {
            require $base_dir.$file;
        }
    }
});

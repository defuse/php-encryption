<?php
/**
 * PSR-4 compatible autoloader
 */
\spl_autoload_register(function ($class) {
    // Project-specific namespace prefix
    $prefix = 'Defuse\\Crypto\\';

    // Base directory for the namespace prefix
    $base_dir = __DIR__.'/src/';
    if (!\function_exists('\\random_int')) {
        require_once $base_dir . '/random_compat/random.php';
    }

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
        'Core' =>
            'Core.php',
        'Crypto' =>
            'Crypto.php',
        'DerivedKeys' =>
            'DerivedKeys.php',
        'Encoding' =>
            'Encoding.php',
        'ExceptionHandler' =>
            'ExceptionHandler.php',
        'File' =>
            'File.php',
        'Key' =>
            'Key.php',
        'KeyOrPassword' =>
            'KeyOrPassword.php',
        'KeyProtectedByPassword' =>
            'KeyProtectedByPassword.php',
        'Salt' =>
            'Salt.php',
        'RuntimeTests' =>
            'RuntimeTests.php',
        'StreamInterface' =>
            'StreamInterface.php',
        // Exceptions:
        'Exception\\BadFormatException' =>
            'Exception/BadFormatException.php',
        'Exception\\CannotPerformOperationException' =>
            'Exception/CannotPerformOperationException.php',
        'Exception\\CryptoException' =>
            'Exception/CryptoException.php',
        'Exception\\IOException' =>
            'Exception/IOException.php',
        'Exception\\WrongKeyOrModifiedCiphertextException' =>
            'Exception/WrongKeyOrModifiedCiphertextException.php',
    );
    foreach ($classmap as $classname => $file) {
        if ($classname === $relative_class) {
            require $base_dir.$file;
        }
    }
});

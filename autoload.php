<?php
/**
 * PSR-4 compatible autoloader
 */
\spl_autoload_register(function ($class) {
    // Project-specific namespace prefix
    $prefix = 'Defuse\\Crypto';

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
    // Since we're on PHP 5.4+ we can use the [] syntax:
    $whitelist = [
        '\\Core',
        '\\Crypto', 
        '\\File',
        '\\ExceptionHandler',
        '\\StreamInterface',
        '\\Exception\\CannotPerformOperationException',
        '\\Exception\\CryptoException',
        '\\Exception\\CryptoTestFailedException',
        '\\Exception\\InvalidCiphertextException',
    ];
    if (!\in_array($relative_class, $whitelist)) {
        var_dump($relative_class);
        // Skip it.
        return;
    }

    // Replace the namespace prefix with the base directory, replace namespace
    // separators with directory separators in the relative class name, append
    // with .php
    $file = $base_dir.
        \str_replace(
            ['\\', '_'],
            '/',
            $relative_class
        ).'.php';

    // If the file exists, require it
    if (\file_exists($file)) {
        require $file;
    }
});

$crypto_exception_handler_object_dont_touch_me = new \Defuse\Crypto\ExceptionHandler;

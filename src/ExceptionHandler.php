<?php
namespace Defuse\Crypto;

use \Defuse\Crypto\Exception as Ex;

/*
 * We want to catch all uncaught exceptions that come from the Crypto class,
 * since by default, PHP will leak the key in the stack trace from an uncaught
 * exception. This is a really ugly hack, but I think it's justified.
 *
 * Everything up to handler() getting called should be reliable, so this should
 * reliably suppress the stack traces. The rest is just a bonus so that we don't
 * make it impossible to debug other exceptions.
 *
 * This bit of code was adapted from: http://stackoverflow.com/a/7939492
 */

class ExceptionHandler
{
    private $rethrow = NULL;

    public function __construct()
    {
        \set_exception_handler(array($this, "handler"));
    }

    public function handler($ex)
    {
        if (
            $ex instanceof Ex\InvalidCiphertextException ||
            $ex instanceof Ex\CannotPerformOperationException ||
            $ex instanceof Ex\CryptoTestFailedException
        ) {
            echo "FATAL ERROR: Uncaught crypto exception. Suppressing output.\n";
        } else {
            /* Re-throw the exception in the destructor. */
            $this->rethrow = $ex;
        }
    }

    public function __destruct() {
        if ($this->rethrow) {
            throw $this->rethrow;
        }
    }
}

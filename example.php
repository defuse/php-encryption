<?php
require_once('Crypto.php');
  try {
      $key = \Defuse\Crypto\Crypto::CreateNewRandomKey();
      // WARNING: Do NOT encode $key with bin2hex() or base64_encode(),
      // they may leak the key to the attacker through side channels.
  } catch (\Defuse\Crypto\CryptoTestFailedException $ex) {
      die('Cannot safely create a key');
  } catch (\Defuse\Crypto\CannotPerformOperationException $ex) {
      die('Cannot safely create a key');
  }

  $message = "ATTACK AT DAWN";
  try {
      $ciphertext = \Defuse\Crypto\Crypto::Encrypt($message, $key);
  } catch (\Defuse\Crypto\CryptoTestFailedException $ex) {
      die('Cannot safely perform encryption');
  } catch (\Defuse\Crypto\CannotPerformOperationException $ex) {
      die('Cannot safely perform decryption');
  }

  try {
      $decrypted = \Defuse\Crypto\Crypto::Decrypt($ciphertext, $key);
  } catch (\Defuse\Crypto\InvalidCiphertextException $ex) { // VERY IMPORTANT
      // Either:
      //   1. The ciphertext was modified by the attacker,
      //   2. The key is wrong, or
      //   3. $ciphertext is not a valid ciphertext or was corrupted.
      // Assume the worst.
      die('DANGER! DANGER! The ciphertext has been tampered with!');
  } catch (\Defuse\Crypto\CryptoTestFailedException $ex) {
      die('Cannot safely perform encryption');
  } catch (\Defuse\Crypto\CannotPerformOperationException $ex) {
      die('Cannot safely perform decryption');
  }
?>

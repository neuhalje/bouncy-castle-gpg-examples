package name.neuhalfen.projects.crypto.bouncycastle.openpgp.roundtrip;


import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages.FULL_USER_ID_SENDER;
import static org.junit.Assert.assertArrayEquals;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.time.Instant;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.DefaultPGPAlgorithmSuites;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPAlgorithmSuite;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPCompressionAlgorithms;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPHashAlgorithms;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPSymmetricEncryptionAlgorithms;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallbacks;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.InMemoryKeyring;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.Configs;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.io.Streams;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class EncryptionDecryptionRoundtripIntegrationTest {


  @SuppressWarnings("WeakerAccess")
  @Parameterized.Parameter
  public /* NOT private */ PGPAlgorithmSuite algorithmSuite;

  /*
   * make sure that the tests work independently of the way the config has been created
   */
  @Parameterized.Parameters
  public static Object[] data() {
    return new Object[]{DefaultPGPAlgorithmSuites.defaultSuiteForGnuPG(),
        DefaultPGPAlgorithmSuites.strongSuite()};
  }

  @Before
  public void installBCProvider() {
    BouncyGPG.registerProvider();
  }

  @Test
  public void encryptAndSignArmored_thenDecryptAndVerify_yieldsOriginalPlaintext()
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
    final byte[] expectedPlaintext = ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes(
        "US-ASCII");

    ByteArrayOutputStream cipherText = new ByteArrayOutputStream();

    final OutputStream encryptionStream = BouncyGPG
        .encryptToStream()
        .withConfig(Configs.keyringConfigFromFilesForSender())
        .withAlgorithms(algorithmSuite)
        .toRecipient("recipient@example.com")
        .andSignWith("sender@example.com")
        .armorAsciiOutput()
        .andWriteTo(cipherText);

    encryptionStream.write(expectedPlaintext);
    encryptionStream.close();
    cipherText.close();

    ByteArrayInputStream cipherTextAsSource = new ByteArrayInputStream(cipherText.toByteArray());

    // Decrypt
    final InputStream decryptedPlaintextStream = BouncyGPG
        .decryptAndVerifyStream()
        .withConfig(Configs.keyringConfigFromResourceForRecipient())
        .andRequireSignatureFromAllKeys("sender@example.com")
        .fromEncryptedInputStream(cipherTextAsSource);

    final byte[] decryptedPlaintext = Streams.readAll(decryptedPlaintextStream);

    assertArrayEquals(expectedPlaintext, decryptedPlaintext);
  }


  @Test
  public void encryptAndSignBinary_thenDecryptAndVerify_yieldsOriginalPlaintext()
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
    final byte[] expectedPlaintext = ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes(
        "US-ASCII");

    ByteArrayOutputStream cipherText = new ByteArrayOutputStream();

    final OutputStream encryptionStream = BouncyGPG
        .encryptToStream()
        .withConfig(Configs.keyringConfigFromFilesForSender())
        .withAlgorithms(algorithmSuite)
        .toRecipient("recipient@example.com")
        .andSignWith("sender@example.com")
        .binaryOutput()
        .andWriteTo(cipherText);

    encryptionStream.write(expectedPlaintext);
    encryptionStream.close();
    cipherText.close();

    ByteArrayInputStream cipherTextAsSource = new ByteArrayInputStream(cipherText.toByteArray());

    // Decrypt
    final InputStream decryptedPlaintextStream = BouncyGPG
        .decryptAndVerifyStream()
        .withConfig(Configs.keyringConfigFromResourceForRecipient())
        .andRequireSignatureFromAllKeys("sender@example.com")
        .fromEncryptedInputStream(cipherTextAsSource);

    final byte[] decryptedPlaintext = Streams.readAll(decryptedPlaintextStream);

    assertArrayEquals(expectedPlaintext, decryptedPlaintext);
  }

  @Test
  public void encryptAndSignTextModeBinary_thenDecryptAndVerify_yieldsOriginalPlaintext()
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
    final byte[] expectedPlaintext = ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes("US-ASCII");

    ByteArrayOutputStream cipherText = new ByteArrayOutputStream();

    final OutputStream encryptionStream = BouncyGPG
        .encryptToStream()
        .withConfig(Configs.keyringConfigFromFilesForSender())
        .withAlgorithms(algorithmSuite)
        .toRecipient("recipient@example.com")
        .andSignWith("sender@example.com")
        .binaryOutput()
        .textMode()
        .andWriteTo(cipherText);

    encryptionStream.write(expectedPlaintext);
    encryptionStream.close();
    cipherText.close();

    ByteArrayInputStream cipherTextAsSource = new ByteArrayInputStream(cipherText.toByteArray());

    // Decrypt
    final InputStream decryptedPlaintextStream = BouncyGPG
        .decryptAndVerifyStream()
        .withConfig(Configs.keyringConfigFromResourceForRecipient())
        .andRequireSignatureFromAllKeys("sender@example.com")
        .fromEncryptedInputStream(cipherTextAsSource);

    final byte[] decryptedPlaintext = Streams.readAll(decryptedPlaintextStream);

    assertArrayEquals(expectedPlaintext, decryptedPlaintext);
  }


  @Test
  public void encryptAndSignBinaryWithSHA256_AES256_thenDecryptAndVerify_yieldsOriginalPlaintext()
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
    final byte[] expectedPlaintext = ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes(
        "US-ASCII");

    ByteArrayOutputStream cipherText = new ByteArrayOutputStream();

    final OutputStream encryptionStream = BouncyGPG
        .encryptToStream()
        .withConfig(Configs.keyringConfigFromFilesForSender())
        .withAlgorithms(new PGPAlgorithmSuite(PGPHashAlgorithms.SHA_256,
            PGPSymmetricEncryptionAlgorithms.AES_256, PGPCompressionAlgorithms.BZIP2))
        .toRecipient("recipient@example.com")
        .andSignWith("sender@example.com")
        .binaryOutput()
        .andWriteTo(cipherText);

    encryptionStream.write(expectedPlaintext);
    encryptionStream.close();
    cipherText.close();

    ByteArrayInputStream cipherTextAsSource = new ByteArrayInputStream(cipherText.toByteArray());

    // Decrypt
    final InputStream decryptedPlaintextStream = BouncyGPG
        .decryptAndVerifyStream()
        .withConfig(Configs.keyringConfigFromResourceForRecipient())
        .andRequireSignatureFromAllKeys("sender@example.com")
        .fromEncryptedInputStream(cipherTextAsSource);

    final byte[] decryptedPlaintext = Streams.readAll(decryptedPlaintextStream);

    assertArrayEquals(expectedPlaintext, decryptedPlaintext);
  }


  @Test
  public void encryptAndSignWithDSA_thenDecryptAndVerify_yieldsOriginalPlaintext()
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
    final byte[] expectedPlaintext = ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes(
        "US-ASCII");

    ByteArrayOutputStream cipherText = new ByteArrayOutputStream();

    final OutputStream encryptionStream = BouncyGPG
        .encryptToStream()
        .withConfig(Configs.keyringConfigFromFilesForSender())
        .withAlgorithms(algorithmSuite)
        .toRecipient("recipient@example.com")
        .andSignWith("sender.signonly@example.com")
        .binaryOutput()
        .andWriteTo(cipherText);

    encryptionStream.write(expectedPlaintext);
    encryptionStream.close();
    cipherText.close();

    ByteArrayInputStream cipherTextAsSource = new ByteArrayInputStream(cipherText.toByteArray());

    // Decrypt
    final InputStream decryptedPlaintextStream = BouncyGPG
        .decryptAndVerifyStream()
        .withConfig(Configs.keyringConfigFromResourceForRecipient())
        .andRequireSignatureFromAllKeys("sender.signonly@example.com")
        .fromEncryptedInputStream(cipherTextAsSource);

    final byte[] decryptedPlaintext = Streams.readAll(decryptedPlaintextStream);

    assertArrayEquals(expectedPlaintext, decryptedPlaintext);
  }


  @Test
  public void encryptBinary_thenDecrypt_yieldsOriginalPlaintext()
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
    final byte[] expectedPlaintext = ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes(
        "US-ASCII");

    ByteArrayOutputStream cipherText = new ByteArrayOutputStream();

    final OutputStream encryptionStream = BouncyGPG
        .encryptToStream()
        .withConfig(Configs.keyringConfigFromFilesForSender())
        .withAlgorithms(algorithmSuite)
        .toRecipient("recipient@example.com")
        .andDoNotSign()
        .binaryOutput()
        .andWriteTo(cipherText);

    encryptionStream.write(expectedPlaintext);
    encryptionStream.close();
    cipherText.close();

    ByteArrayInputStream cipherTextAsSource = new ByteArrayInputStream(cipherText.toByteArray());

    // Decrypt
    final InputStream decryptedPlaintextStream = BouncyGPG
        .decryptAndVerifyStream()
        .withConfig(Configs.keyringConfigFromResourceForRecipient())
        .andIgnoreSignatures()
        .fromEncryptedInputStream(cipherTextAsSource);

    final byte[] decryptedPlaintext = Streams.readAll(decryptedPlaintextStream);

    assertArrayEquals(expectedPlaintext, decryptedPlaintext);
  }

  /*
   * This setup does not work. Keep the test as an example of how NOT to do it.
   */
  @Test(expected = EOFException.class)
  public void encryptInTryWithResources_decryptInTryWithRessources_fails()
      throws IOException, PGPException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException {
    ByteArrayOutputStream result = new ByteArrayOutputStream();

    try (
        final OutputStream outputStream = BouncyGPG
            .encryptToStream()
            .withConfig(Configs.keyringConfigFromFilesForSender())
            .withStrongAlgorithms()
            .toRecipient("recipient@example.com")
            .andSignWith("sender@example.com")
            .binaryOutput()
            .andWriteTo(
                new BufferedOutputStream(result, 16384));

        final InputStream is = new ByteArrayInputStream(
            ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes())
    ) {
      Streams.pipeAll(is, outputStream);
    }

    final byte[] ciphertext = result.toByteArray();
    final ByteArrayOutputStream plainBA = new ByteArrayOutputStream();

    try (
        final InputStream plainIS = BouncyGPG.decryptAndVerifyStream()
            .withConfig(Configs.keyringConfigFromFilesForRecipient())
            .andRequireSignatureFromAllKeys("sender@example.com")
            .fromEncryptedInputStream(new ByteArrayInputStream(ciphertext))

    ) {
      Streams.pipeAll(plainIS, plainBA);
    }

    assertArrayEquals(ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes(), plainBA.toByteArray());
  }


  /*
   * This setup DOES work. Keep the test as an example of how to to do it.
   */
  @Test()
  public void encryptInTryWithResources_decryptInTryWithRessources_yieldsOriginalPlaintext()
      throws IOException, PGPException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException {
    ByteArrayOutputStream result = new ByteArrayOutputStream();

    try (
        BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(result, 16384);
        final OutputStream outputStream = BouncyGPG
            .encryptToStream()
            .withConfig(Configs.keyringConfigFromFilesForSender())
            .withAlgorithms(algorithmSuite)
            .toRecipient("recipient@example.com")
            .andSignWith("sender@example.com")
            .binaryOutput()
            .andWriteTo(
                bufferedOutputStream);

        final InputStream is = new ByteArrayInputStream(
            ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes())
    ) {
      Streams.pipeAll(is, outputStream);
    }

    final byte[] ciphertext = result.toByteArray();
    final ByteArrayOutputStream plainBA = new ByteArrayOutputStream();

    try (
        final InputStream plainIS = BouncyGPG.decryptAndVerifyStream()
            .withConfig(Configs.keyringConfigFromFilesForRecipient())
            .andRequireSignatureFromAllKeys("sender@example.com")
            .fromEncryptedInputStream(new ByteArrayInputStream(ciphertext))

    ) {
      Streams.pipeAll(plainIS, plainBA);
    }

    assertArrayEquals(ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes(), plainBA.toByteArray());
  }


  @Test
  public void encrypt_decrypt_yieldsOriginalPlaintext()
      throws IOException, PGPException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException {
    ByteArrayOutputStream result = new ByteArrayOutputStream();
    BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(result, 16384 * 1024);

    final OutputStream outputStream = BouncyGPG
        .encryptToStream()
        .withConfig(Configs.keyringConfigFromFilesForSender())
        .setReferenceDateForKeyValidityTo(Instant.MAX)
        .withAlgorithms(algorithmSuite)
        .toRecipient("recipient@example.com")
        .andSignWith("sender@example.com")
        .binaryOutput()
        .andWriteTo(bufferedOutputStream);

    final InputStream is = new ByteArrayInputStream(
        ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes());
    Streams.pipeAll(is, outputStream);
    outputStream.close();
    bufferedOutputStream.close();
    is.close();

    final byte[] ciphertext = result.toByteArray();
    final ByteArrayOutputStream plainBA = new ByteArrayOutputStream();

    final InputStream plainIS = BouncyGPG.decryptAndVerifyStream()
        .withConfig(Configs.keyringConfigFromFilesForRecipient())
        .andRequireSignatureFromAllKeys("sender@example.com")
        .fromEncryptedInputStream(new ByteArrayInputStream(ciphertext));

    Streams.pipeAll(plainIS, plainBA);

    assertArrayEquals(ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes(), plainBA.toByteArray());
  }


  @Test
  public void encryptByteByByte_decryptByteByByte_yieldsOriginalPlaintext()
      throws IOException, PGPException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException {
    ByteArrayOutputStream result = new ByteArrayOutputStream();
    BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(result, 16384 * 1024);

    final OutputStream outputStream = BouncyGPG
        .encryptToStream()
        .withConfig(Configs.keyringConfigFromFilesForSender())
        .withAlgorithms(algorithmSuite)
        .toRecipient("recipient@example.com")
        .andSignWith("sender@example.com")
        .binaryOutput()
        .andWriteTo(bufferedOutputStream);

    final InputStream is = new ByteArrayInputStream(
        ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes());

    int b;
    // Copy byte-by-byte to test these edge-cases
    while ((b = is.read()) > 0) {
      outputStream.write(b);
    }

    Streams.pipeAll(is, outputStream);

    outputStream.close();
    bufferedOutputStream.close();
    is.close();

    final byte[] ciphertext = result.toByteArray();
    final ByteArrayOutputStream plainBA = new ByteArrayOutputStream();

    final InputStream plainIS = BouncyGPG.decryptAndVerifyStream()
        .withConfig(Configs.keyringConfigFromFilesForRecipient())
        .andRequireSignatureFromAllKeys("sender@example.com")
        .fromEncryptedInputStream(new ByteArrayInputStream(ciphertext));

    // Copy byte-by-byte to test these edge-cases
    while ((b = plainIS.read()) > 0) {
      plainBA.write(b);
    }

    assertArrayEquals(ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes(), plainBA.toByteArray());
  }


  @Test
  public void encryptWithOnlyPubkeyInRing_decryptWithOnlyPrivKeyInring_yieldsOriginalPlaintext()
      throws IOException, PGPException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException {

    final byte[] ciphertext;
    {
      ByteArrayOutputStream result = new ByteArrayOutputStream();
      BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(result);

      final InMemoryKeyring encryptionKeyring = KeyringConfigs
          .forGpgExportedKeys(KeyringConfigCallbacks.withUnprotectedKeys());
      encryptionKeyring.addPublicKey(ExampleMessages.PUBKEY_RECIPIENT.getBytes());

      final OutputStream outputStream = BouncyGPG
          .encryptToStream()
          .withConfig(encryptionKeyring)
          .withAlgorithms(algorithmSuite)
          .toRecipient("recipient@example.com")
          .andDoNotSign()
          .binaryOutput()
          .andWriteTo(bufferedOutputStream);

      final InputStream is = new ByteArrayInputStream(
          ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes());
      Streams.pipeAll(is, outputStream);
      outputStream.close();
      bufferedOutputStream.close();
      is.close();
      ciphertext = result.toByteArray();
    }

    // Decrypt

    {
      final InMemoryKeyring decryptionKeyring = KeyringConfigs
          .forGpgExportedKeys(KeyringConfigCallbacks.withPassword("recipient"));
      decryptionKeyring.addSecretKey(ExampleMessages.SECRET_KEY_RECIPIENT.getBytes());

      final ByteArrayOutputStream plainBA = new ByteArrayOutputStream();

      final InputStream plainIS = BouncyGPG.decryptAndVerifyStream()
          .withConfig(decryptionKeyring)
          .andIgnoreSignatures()
          .fromEncryptedInputStream(new ByteArrayInputStream(ciphertext));

      Streams.pipeAll(plainIS, plainBA);

      assertArrayEquals(ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes(), plainBA.toByteArray());
    }
  }


  @Test
  public void encryptMultipleRecipients_decrypt_yieldsOriginalPlaintext()
      throws IOException, PGPException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException {
    ByteArrayOutputStream result = new ByteArrayOutputStream();
    BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(result, 16384 * 1024);

    final OutputStream outputStream = BouncyGPG
        .encryptToStream()
        .withConfig(Configs.keyringConfigFromResourceForSender())
        .setReferenceDateForKeyValidityTo(Instant.MAX)
        .withAlgorithms(algorithmSuite)
        .toRecipients("sender@example.com", "recipient@example.com")
        .andSignWith("sender@example.com")
        .binaryOutput()
        .andWriteTo(bufferedOutputStream);

    final InputStream is = new ByteArrayInputStream(
        ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes());
    Streams.pipeAll(is, outputStream);
    outputStream.close();
    bufferedOutputStream.close();
    is.close();

    final byte[] ciphertext = result.toByteArray();
    final ByteArrayOutputStream plainBA = new ByteArrayOutputStream();

    final InputStream plainIS = BouncyGPG.decryptAndVerifyStream()
        .withConfig(Configs.keyringConfigFromFilesForRecipient())
        .andRequireSignatureFromAllKeys("sender@example.com")
        .fromEncryptedInputStream(new ByteArrayInputStream(ciphertext));

    Streams.pipeAll(plainIS, plainBA);

    assertArrayEquals(ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes(), plainBA.toByteArray());
  }


  @Test
  public void changingKeySelection_selectUidByAnyUidPart_works()
      throws IOException, PGPException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException {
    ByteArrayOutputStream result = new ByteArrayOutputStream();
    BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(result);

    final OutputStream outputStream = BouncyGPG
        .encryptToStream()
        .withConfig(Configs.keyringConfigFromFilesForSender())
        .selectUidByAnyUidPart()
        .setReferenceDateForKeyValidityTo(Instant.MAX)
        .withAlgorithms(algorithmSuite)
        .toRecipient("<recipient@example.com>")
        .andSignWith(FULL_USER_ID_SENDER)
        .binaryOutput()
        .andWriteTo(bufferedOutputStream);

    final InputStream is = new ByteArrayInputStream(
        ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes());
    Streams.pipeAll(is, outputStream);
    outputStream.close();
    bufferedOutputStream.close();
    is.close();

    final byte[] ciphertext = result.toByteArray();
    final ByteArrayOutputStream plainBA = new ByteArrayOutputStream();

    final InputStream plainIS = BouncyGPG.decryptAndVerifyStream()
        .withConfig(Configs.keyringConfigFromFilesForRecipient())
        .selectUidByAnyUidPart()
        .andRequireSignatureFromAllKeys("Sven Sender")
        .fromEncryptedInputStream(new ByteArrayInputStream(ciphertext));

    Streams.pipeAll(plainIS, plainBA);

    assertArrayEquals(ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes(), plainBA.toByteArray());
  }
}

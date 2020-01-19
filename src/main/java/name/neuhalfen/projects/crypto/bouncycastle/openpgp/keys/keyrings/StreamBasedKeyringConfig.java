package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings;

import static java.util.Objects.requireNonNull;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallback;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

/**
 * Implements a keyring based on streams. The streams provide the GPG on-disk
 * files.
 * @deprecated : The keyring configs are highly dependent on GnuPG. Using secret keys no longer works with GnuPG 2.1
 */
@Deprecated
final class StreamBasedKeyringConfig implements KeyringConfig {

  @Nonnull
  private final KeyringConfigCallback callback;
  private final PGPPublicKeyRingCollection publicKeyRings;
  private final PGPSecretKeyRingCollection secretKeyRings;
  private final KeyFingerPrintCalculator keyFingerPrintCalculator;

  /**
   * @param callback Callback to resolve secret key passwords
   * @param publicKeyRings public keyring, can be empty.
   * @param secretKeyRings secret keyring, can be empty.
   */
  private StreamBasedKeyringConfig(KeyringConfigCallback callback,
      KeyFingerPrintCalculator keyFingerPrintCalculator,
      PGPPublicKeyRingCollection publicKeyRings,
      PGPSecretKeyRingCollection secretKeyRings) {

    this.callback = callback;
    this.keyFingerPrintCalculator = keyFingerPrintCalculator;
    this.publicKeyRings = publicKeyRings;
    this.secretKeyRings = secretKeyRings;
  }

  /**
   * @param callback Callback to provide paraphrases
   * @param publicKeyringStream GPG keyring "public keys" file, will be closed. null --> empty
   *     keyring
   * @param secretKeyringStream GPG keyring "private keys" file, will be closed. null --> empty
   *     keyring
   */
  @SuppressWarnings("PMD.DefaultPackage")
  static KeyringConfig build(
      KeyringConfigCallback callback,
      @Nullable InputStream publicKeyringStream,
      @Nullable InputStream secretKeyringStream) throws IOException, PGPException {

    requireNonNull(callback, "callback must not be null");

    final KeyFingerPrintCalculator keyFingerPrintCalculator = new BcKeyFingerprintCalculator();

    final PGPPublicKeyRingCollection publicKeyRings;

    if (publicKeyringStream == null) {
      publicKeyRings = new
          PGPPublicKeyRingCollection(Collections.EMPTY_LIST);
    } else {
      publicKeyRings = new
          PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(publicKeyringStream),
          keyFingerPrintCalculator);
      close(publicKeyringStream);
    }

    final PGPSecretKeyRingCollection secretKeyRings;

    if (secretKeyringStream == null) {
      secretKeyRings = new PGPSecretKeyRingCollection(Collections.EMPTY_LIST);
    } else {
      secretKeyRings = new
          PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(secretKeyringStream),
          keyFingerPrintCalculator);
      close(secretKeyringStream);
    }

    return new StreamBasedKeyringConfig(callback, keyFingerPrintCalculator, publicKeyRings,
        secretKeyRings);

  }

  private static void close(InputStream stream) {
    if (stream != null) {
      try {
        stream.close();
      } catch (IOException e) { // NOPMD: EmptyCatchBlock
        /* Ignore */
      }
    }
  }

  @SuppressWarnings("PMD.ShortVariable")
  @Override
  public String toString() {
    return "StreamBasedKeyringConfig{"
        + "callback="
        + callback
        + ", publicKeyRings=" + publicKeyRings
        + ", secretKeyRings=" + (secretKeyRings == null ? "null" : "<present>")
        + '}';
  }

  @Override
  public PGPPublicKeyRingCollection getPublicKeyRings() throws IOException, PGPException {
    return publicKeyRings;
  }

  @Override
  public PGPSecretKeyRingCollection getSecretKeyRings() throws IOException, PGPException {
    return secretKeyRings;
  }

  @Override
  public
  @Nullable
  char[] decryptionSecretKeyPassphraseForSecretKeyId(long keyID) {
    return callback.decryptionSecretKeyPassphraseForSecretKeyId(keyID);
  }

  @Override
  public KeyFingerPrintCalculator getKeyFingerPrintCalculator() {
    return keyFingerPrintCalculator;
  }

}

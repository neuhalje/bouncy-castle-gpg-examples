package name.neuhalfen.projects.crypto.bouncycastle.openpgp.encrypting;


import static java.util.Objects.requireNonNull;

import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Date;
import java.util.Iterator;
import java.util.Set;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPAlgorithmSuite;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.PGPUtilities;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeySelectionStrategy;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeySelectionStrategy.PURPOSE;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.internal.Preconditions;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;

@SuppressWarnings("PMD.ExcessiveImports")
public final class PGPEncryptingStream extends OutputStream {

  private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory
      .getLogger(PGPEncryptingStream.class);

  private final KeyringConfig config;
  private final PGPAlgorithmSuite algorithmSuite;
  private boolean isDoSign;
  /**
   * The signature uid.
   */
  private OutputStream encryptionDataStream;
  private PGPSignatureGenerator signatureGenerator;

  @Nullable
  private ArmoredOutputStream armoredOutputStream;
  private OutputStream outerEncryptionStream;
  private BCPGOutputStream compressionStream;
  private PGPLiteralDataGenerator encryptionDataStreamGenerator;
  private PGPCompressedDataGenerator compressionStreamGenerator;

  /*
   * true would mean "This stream is _already_ closed"
   */
  private boolean isClosed = false; // NOPMD: RedundantFieldInitializer

  private PGPEncryptingStream(final KeyringConfig config, final PGPAlgorithmSuite algorithmSuite) {
    super();
    this.config = config;
    this.algorithmSuite = algorithmSuite;
  }

  /**
   * Return a stream that, when written plaintext into, writes the ciphertext into cipherTextSink.
   *
   * @param config key configuration
   * @param algorithmSuite algorithm suite to use.
   * @param signingUid sign with this uid (optionally)
   * @param cipherTextSink write the ciphertext in here
   * @param keySelectionStrategy selection strategy
   * @param armor armor the file (true) or use binary.
   * @param encryptTo encrypt to
   * @param textMode simulates GnuPG's {@code --textmode} flag
   *
   * @return stream where plaintext gets written into
   *
   * @throws IOException streams, IO, ...
   * @throws PGPException pgp error
   * @throws NoSuchAlgorithmException algorithmSuite not supported
   * @throws NoSuchProviderException bouncy castle not registered
   * @see name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.DefaultPGPAlgorithmSuites
   */
  public static OutputStream create(final KeyringConfig config,
      final PGPAlgorithmSuite algorithmSuite,
      @Nullable final String signingUid,
      final OutputStream cipherTextSink,
      final KeySelectionStrategy keySelectionStrategy,
      final boolean armor,
      final Set<PGPPublicKey> encryptTo,
      final boolean textMode)
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException {

    requireNonNull(config, "callback must not be null");
    requireNonNull(cipherTextSink, "cipherTextSink must not be null");
    requireNonNull(encryptTo, "pubEncKeys must not be null");
    Preconditions.checkArgument(!encryptTo.isEmpty(), "pubEncKeys must not be empty");

    for (final PGPPublicKey pubEncKey : encryptTo) {
      if (!pubEncKey.isEncryptionKey()) {
        throw new PGPException(String
            .format("This public key (0x%x) is not suitable for encryption", pubEncKey.getKeyID()));
      }
    }

    final PGPEncryptingStream encryptingStream = new PGPEncryptingStream(config, algorithmSuite);
    encryptingStream.setup(cipherTextSink, signingUid, encryptTo, keySelectionStrategy, armor, textMode);
    return encryptingStream;
  }


  /**
   * Internal method to set up the stream.
   *
   * @param cipherTextSink Where the ciphertext goes
   * @param signingUid Sign with this uid. null: do not sign
   * @param pubEncKeys the pub enc keys
   * @param keySelectionStrategy key selection strategy (for signatures)
   * @param armor if OutputStream should be "armored", that means base64 encoded
   * @param textMode simulates GnuPG's {@code --textmode} flag
   *
   * @throws IOException Signals that an I/O exception has occurred.
   * @throws PGPException the pGP exception
   * @see org.bouncycastle.bcpg.HashAlgorithmTags
   * @see org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
   */
  @SuppressWarnings({"PMD.LawOfDemeter", "PMD.AvoidInstantiatingObjectsInLoops",
      "PMD.CyclomaticComplexity"})
  private void setup(final OutputStream cipherTextSink,
      @Nullable final String signingUid,
      final Set<PGPPublicKey> pubEncKeys,
      final KeySelectionStrategy keySelectionStrategy,
      final boolean armor,
      final boolean textMode) throws
      IOException, PGPException {
    isDoSign = signingUid != null;

    final OutputStream sink; // NOPMD: PGPEncryptingStream
    if (armor) {
      this.armoredOutputStream = new ArmoredOutputStream(cipherTextSink);
      sink = this.armoredOutputStream;
    } else {
      sink = cipherTextSink;
    }

    final BcPGPDataEncryptorBuilder dataEncryptorBuilder = new BcPGPDataEncryptorBuilder(
        algorithmSuite.getSymmetricEncryptionAlgorithmCode().getAlgorithmId());
    dataEncryptorBuilder.setWithIntegrityPacket(true);

    final PGPEncryptedDataGenerator cPk =
        new PGPEncryptedDataGenerator(dataEncryptorBuilder);

    for (final PGPPublicKey pubEncKey : pubEncKeys) {
      cPk.addMethod(
          new BcPublicKeyKeyEncryptionMethodGenerator(
              pubEncKey));
    }

    // this wraps the output stream in an encrypting output stream
    outerEncryptionStream = cPk.open(sink, new byte[4096]);

    if (isDoSign) {
      final PGPPublicKey signingPublicKey = keySelectionStrategy
          .selectPublicKey(PURPOSE.FOR_SIGNING, signingUid, config);
      if (signingPublicKey == null) {
        throw new PGPException(
            "No suitable public key found for signing with uid: '" + signingUid + "'");
      }
      LOGGER.trace("Signing for uid '{}' with key 0x{}.", signingUid,
          Long.toHexString(signingPublicKey.getKeyID()));

      final PGPSecretKey pgpSec = config.getSecretKeyRings()
          .getSecretKey(signingPublicKey.getKeyID());
      if (pgpSec == null) {
        throw new PGPException(
            "No suitable private key found for signing with uid: '" + signingUid
                + "' (although found pubkey: " + signingPublicKey.getKeyID() + ")");
      }

      final PGPPrivateKey pgpPrivKey = PGPUtilities.extractPrivateKey(pgpSec,
          config.decryptionSecretKeyPassphraseForSecretKeyId(pgpSec.getKeyID()));
      signatureGenerator = new PGPSignatureGenerator(
          new BcPGPContentSignerBuilder(pgpSec.getPublicKey().getAlgorithm(),
              algorithmSuite.getHashAlgorithmCode().getAlgorithmId()));

      signatureGenerator.init(textMode ? PGPSignature.CANONICAL_TEXT_DOCUMENT : PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

      final Iterator<?> userIDs = pgpSec.getPublicKey().getUserIDs();
      if (userIDs.hasNext()) {
        final PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();

        spGen.setSignerUserID(false, (String) userIDs.next());
        signatureGenerator.setHashedSubpackets(spGen.generate());
      }
    }

    compressionStreamGenerator = new PGPCompressedDataGenerator(
        algorithmSuite.getCompressionEncryptionAlgorithmCode().getAlgorithmId());
    compressionStream = new BCPGOutputStream(
        compressionStreamGenerator.open(outerEncryptionStream));

    if (isDoSign) {
      signatureGenerator.generateOnePassVersion(false).encode(compressionStream);
    }

    encryptionDataStreamGenerator = new PGPLiteralDataGenerator();
    encryptionDataStream = encryptionDataStreamGenerator
        .open(compressionStream, textMode ? PGPLiteralData.TEXT : PGPLiteralData.BINARY, "", new Date(), new byte[1 << 16]);
  }

  @Override
  public void write(int data) throws IOException {
    encryptionDataStream.write(data);

    if (isDoSign) {
      final byte asByte = (byte) (data & 0xff);
      signatureGenerator.update(asByte);
    }
  }


  @Override
  public void write(@Nonnull byte[] buffer) throws IOException {
    write(buffer, 0, buffer.length);
  }


  @Override
  public void write(@Nonnull byte[] buffer, int off, int len) throws IOException {
    encryptionDataStream.write(buffer, 0, len);
    if (isDoSign) {
      signatureGenerator.update(buffer, 0, len);
    }
  }

  @Override
  public void flush() throws IOException {
    encryptionDataStream.flush();
  }

  @Override
  public void close() throws IOException {
    if (!isClosed) {

      encryptionDataStream.flush();
      encryptionDataStream.close();
      encryptionDataStreamGenerator.close();
      if (isDoSign) {

        try {
          signatureGenerator.generate().encode(compressionStream);  // NOPMD:  Demeter (BC API)
        } catch (PGPException e) {
          throw new IOException(e);
        }
      }
      compressionStreamGenerator.close();

      outerEncryptionStream.flush();
      outerEncryptionStream.close();

      if (armoredOutputStream != null) {
        armoredOutputStream.flush();
        armoredOutputStream.close();
      }
      isClosed = true;
    }
  }
}

package name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting;

import static java.util.Objects.requireNonNull;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nonnull;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.validation.SignatureValidationStrategy;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;

@SuppressWarnings("PMD.ShortVariable")
final class SignatureValidatingInputStream extends FilterInputStream {

  private final DecryptionState state;
  private final SignatureValidationStrategy signatureValidationStrategy;

  /**
   * Creates a <code>SignatureValidatingInputStream</code> by assigning the  argument
   * <code>inputStream</code> to the field <code>this.inputStream</code> so as to remember it for
   * later use.
   *
   * @param inputStream the underlying input stream, or <code>null</code> if this instance is to
   *     be
   *     created without an underlying stream.
   */
  SignatureValidatingInputStream(InputStream inputStream, DecryptionState state,
      SignatureValidationStrategy signatureValidationStrategy) {
    super(inputStream);
    requireNonNull(state, "state must not be null");
    requireNonNull(signatureValidationStrategy,
        "signatureValidationStrategy must not be null");

    this.state = state;
    this.signatureValidationStrategy = signatureValidationStrategy;
  }

  @Override
  public int read() throws IOException {
    final int data = super.read();
    final boolean endOfStream = data == -1;
    if (endOfStream) {
      validateSignature();
    } else {
      state.updateOnePassSignatures((byte) data);
    }
    return data;
  }

  @Override
  public int read(@Nonnull byte[] b) throws IOException {
    return read(b, 0, b.length);
  }

  @Override
  public int read(@Nonnull byte[] b, int off, int len) throws IOException {
    final int read = super.read(b, off, len);

    final boolean endOfStream = read == -1;
    if (endOfStream) {
      validateSignature();
    } else {
      state.updateOnePassSignatures(b, off, read);
    }
    return read;
  }

  /**
   * Ensure that at least ONE signature is valid.
   *
   * @throws IOException No valid signature found
   */
  private void validateSignature() throws IOException {
    try {
      signatureValidationStrategy
          .validateSignatures(state.getSignatureFactory(), state.getOnePassSignatures());
    } catch (PGPException | SignatureException e) {
      throw new IOException(e.getMessage(), e);
    }

  }

  @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
  @Override
  public synchronized void mark(int readlimit) {
    throw new UnsupportedOperationException("mark not supported");
  }

  @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
  @Override
  public synchronized void reset() throws IOException {
    throw new UnsupportedOperationException("reset not supported");
  }

  @Override
  public boolean markSupported() {
    return false;
  }

  @SuppressWarnings("PMD.DefaultPackage")
  static final class DecryptionState {

    private final Map<Long, PGPOnePassSignature> onePassSignatures = new HashMap<>();
    private PGPObjectFactory signatureFactory;

    @SuppressWarnings("PMD.DefaultPackage")
    PGPObjectFactory getSignatureFactory() {
      return signatureFactory;
    }

    @SuppressWarnings("PMD.DefaultPackage")
    void setSignatureFactory(PGPObjectFactory signatureFactory) {
      this.signatureFactory = signatureFactory;
    }


    @SuppressWarnings("PMD.DefaultPackage")
    void updateOnePassSignatures(byte data) {
      for (final PGPOnePassSignature sig : onePassSignatures.values()) {
        sig.update(data);
      }
    }

    @SuppressWarnings("PMD.DefaultPackage")
    void updateOnePassSignatures(byte[] b, int off, int len) {
      for (final PGPOnePassSignature sig : onePassSignatures.values()) {
        sig.update(b, off, len);
      }
    }

    @SuppressWarnings("PMD.DefaultPackage")
    Map<Long, PGPOnePassSignature> getOnePassSignatures() {
      return onePassSignatures;
    }

    /*
     * @pre: the public key for the keyId is in our keyring.
     */
    @SuppressWarnings("PMD.DefaultPackage")
    void addSignature(PGPOnePassSignature signature) {
      onePassSignatures.put(signature.getKeyID(), signature);
    }

    @SuppressWarnings("PMD.DefaultPackage")
    int numVerifiableSignatures() {
      return onePassSignatures.size();
    }

    @SuppressWarnings("PMD.DefaultPackage")
    boolean hasVerifiableSignatures() {
      return numVerifiableSignatures() > 0;
    }
  }
}

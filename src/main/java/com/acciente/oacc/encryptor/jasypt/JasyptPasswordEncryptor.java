/*
 * Copyright 2009-2017, Acciente LLC
 *
 * Acciente LLC licenses this file to you under the
 * Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the
 * License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in
 * writing, software distributed under the License is
 * distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
 * OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing
 * permissions and limitations under the License.
 */
package com.acciente.oacc.encryptor.jasypt;

import com.acciente.oacc.encryptor.PasswordEncryptor;
import org.jasypt.normalization.Normalizer;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class JasyptPasswordEncryptor implements PasswordEncryptor, Serializable {
   public static final String NAME = "jasypt";

   private static final String DEFAULT_ENCRYPT_ALGORITHM       = "SHA-256";
   private static final int    DEFAULT_ENCRYPT_ITERATIONS      = 100000;
   private static final int    DEFAULT_ENCRYPT_SALT_SIZE_BYTES = 16;

   private static final String MARKER          = NAME + ":";
   private static final String PARAM_DELIMITER = "$";

   private static final StandardByteDigesterPool digesterPool       = new StandardByteDigesterPool();
   private static final HashEncoderDecoder       hashEncoderDecoder = new HashEncoderDecoder(MARKER, PARAM_DELIMITER);

   private final String encryptAlgorithm;
   private final int    encryptIterations;
   private final int    encryptSaltSizeBytes;

   public static JasyptPasswordEncryptor getPasswordEncryptor() {
      return getPasswordEncryptor(DEFAULT_ENCRYPT_ALGORITHM, DEFAULT_ENCRYPT_ITERATIONS, DEFAULT_ENCRYPT_SALT_SIZE_BYTES);
   }

   public static JasyptPasswordEncryptor getPasswordEncryptor(String encryptAlgorithm,
                                                              int encryptIterations,
                                                              int encryptSaltSizeBytes) {
      return new JasyptPasswordEncryptor(encryptAlgorithm, encryptIterations, encryptSaltSizeBytes);
   }

   private JasyptPasswordEncryptor(String encryptAlgorithm, int encryptIterations, int encryptSaltSizeBytes) {
      this.encryptAlgorithm = encryptAlgorithm;
      this.encryptIterations = encryptIterations;
      this.encryptSaltSizeBytes = encryptSaltSizeBytes;
   }

   @Override
   public String encryptPassword(final char[] password) {
      if (password == null) {
         return null;
      }

      final byte[] encryptedPassword = digesterPool
            .getStandardByteDigester(encryptAlgorithm, encryptIterations, encryptSaltSizeBytes)
            .digest(getCleanedBytes(password));

      return hashEncoderDecoder.encodeHash(encryptAlgorithm, encryptIterations, encryptSaltSizeBytes, encryptedPassword);
   }

   @Override
   public boolean checkPassword(final char[] plainPassword,
                                final String encodedPasswordHash) {
      if (plainPassword == null) {
         return (encodedPasswordHash == null);
      }
      else if (encodedPasswordHash == null) {
         return false;
      }

      final DecodedHash decodedHash = hashEncoderDecoder.decodeHash(encodedPasswordHash);
      return digesterPool.getStandardByteDigester(decodedHash.getEncryptAlgorithm(),
                                                  decodedHash.getEncryptIterations(),
                                                  decodedHash.getEncryptSaltSizeBytes())
            .matches(getCleanedBytes(plainPassword), decodedHash.getEncryptedPassword());
   }

   private static byte[] getCleanedBytes(char[] password) {
      final ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(Normalizer.normalizeToNfc(password)));
      final byte[]     byteArray  = new byte[byteBuffer.remaining()];
      byteBuffer.get(byteArray);
      Arrays.fill(byteBuffer.array(), (byte) 0);
      return byteArray;
   }

}

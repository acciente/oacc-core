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
import com.acciente.oacc.normalizer.TextNormalizer;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Password encryptor implementation that uses the Jasypt digester for creating password hashes.
 */
public final class JasyptPasswordEncryptor implements PasswordEncryptor, Serializable {
   private static final long serialVersionUID = 1L;

   public static final String NAME = "jasypt";

   private static final StandardByteDigesterPool digesterPool           = new StandardByteDigesterPool();
   private static final PasswordEncoderDecoder   passwordEncoderDecoder = new PasswordEncoderDecoder();

   private final String algorithm;
   private final int    iterations;
   private final int    saltSizeBytes;

   /**
    * Creates a password encryptor that uses the Jasypt digester for password hashing with the specified values for
    * algorithm, iterations and saltSizeBytes.
    *
    * @param algorithm     the name of the message digest algorithm to be used for password hashing.
    *                      See the MessageDigest section in the <a href=
    *                      "https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#MessageDigest">
    *                      Java Cryptography Architecture Standard Algorithm Name Documentation</a>
    *                      for information about standard algorithm names.
    * @param iterations    the number of times the password hash function will be applied recursively
    * @param saltSizeBytes the size of the salt to be used, in bytes
    * @return a {@link JasyptPasswordEncryptor} instance.
    */
   public static JasyptPasswordEncryptor newInstance(String algorithm,
                                                     int iterations,
                                                     int saltSizeBytes) {
      return new JasyptPasswordEncryptor(algorithm, iterations, saltSizeBytes);
   }

   private JasyptPasswordEncryptor(String algorithm, int iterations, int saltSizeBytes) {
      this.algorithm = algorithm;
      this.iterations = iterations;
      this.saltSizeBytes = saltSizeBytes;
   }

   @Override
   public String encryptPassword(final char[] plainPassword) {
      if (plainPassword == null) {
         return null;
      }

      final byte[] digest = digesterPool.getStandardByteDigester(algorithm, iterations, saltSizeBytes)
            .digest(getCleanedBytes(plainPassword));

      return passwordEncoderDecoder.encode(algorithm, iterations, saltSizeBytes, digest);
   }

   @Override
   public boolean checkPassword(final char[] plainPassword,
                                final String storedPassword) {
      if (plainPassword == null) {
         return (storedPassword == null);
      }
      else if (storedPassword == null) {
         return false;
      }

      final DecodedPassword decodedPassword = passwordEncoderDecoder.decode(storedPassword);
      return digesterPool.getStandardByteDigester(decodedPassword.getAlgorithm(),
                                                  decodedPassword.getIterations(),
                                                  decodedPassword.getSaltSizeBytes())
            .matches(getCleanedBytes(plainPassword), decodedPassword.getDigest());
   }

   private static byte[] getCleanedBytes(char[] password) {
      final char[] normalizedChars = TextNormalizer.getInstance().normalizeToNfc(password);
      final ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(normalizedChars));
      final byte[]     byteArray  = new byte[byteBuffer.remaining()];
      byteBuffer.get(byteArray);
      Arrays.fill(byteBuffer.array(), (byte) 0);
      return byteArray;
   }
}

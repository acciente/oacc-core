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
package com.acciente.oacc.encryptor.bcrypt;

import com.acciente.oacc.encryptor.PasswordEncryptor;
import com.acciente.oacc.normalizer.TextNormalizer;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;

import java.io.Serializable;
import java.security.SecureRandom;

/**
 * Password encryptor implementation that uses the OpenBSD BCrypt algorithm for creating password hashes.
 */
public class BCryptPasswordEncryptor implements PasswordEncryptor, Serializable {
   private static final long serialVersionUID = 1L;

   public static final String NAME = "bcrypt";

   private static final int BCRYPT_COST_FACTOR_MIN = 4;
   private static final int BCRYPT_COST_FACTOR_MAX = 31;
   private static final int BCRYPT_SALT_SIZE       = 16;

   private static final PasswordEncoderDecoder passwordEncoderDecoder = new PasswordEncoderDecoder();
   private static final SecureRandom           secureRandom           = new SecureRandom();

   private final int costFactor;

   /**
    * Returns a password encryptor that uses the BCrypt algorithm with the specified cost factor.
    *
    * @param costFactor the BCrypt cost factor, must be between {@value BCRYPT_COST_FACTOR_MIN} and
    *                   {@value BCRYPT_COST_FACTOR_MAX} (inclusive).
    * @return a BCryptPasswordEncryptor instance configured as described above.
    * @throws IllegalArgumentException if the specified BCrypt cost factor is not between {@value BCRYPT_COST_FACTOR_MIN}
    *                                  and {@value BCRYPT_COST_FACTOR_MAX} (inclusive).
    */
   public static BCryptPasswordEncryptor newInstance(int costFactor) {
      assertCostFactorValid(costFactor);
      return new BCryptPasswordEncryptor(costFactor);
   }

   private BCryptPasswordEncryptor(int costFactor) {
      this.costFactor = costFactor;
   }

   @Override
   public String encryptPassword(char[] plainPassword) {
      if (plainPassword == null) {
         return null;
      }
      final char[] normalizedChars = TextNormalizer.getInstance().normalizeToNfc(plainPassword);

      final String bcryptString = OpenBSDBCrypt.generate(normalizedChars, gensalt(), costFactor /* log rounds */);

      return passwordEncoderDecoder.encode(bcryptString);
   }

   @Override
   public boolean checkPassword(char[] plainPassword, String storedPassword) {
      if (plainPassword == null) {
         return (storedPassword == null);
      }
      else if (storedPassword == null) {
         return false;
      }

      final String bcryptString = passwordEncoderDecoder.decode(storedPassword);
      final char[] normalizedChars = TextNormalizer.getInstance().normalizeToNfc(plainPassword);

      return OpenBSDBCrypt.checkPassword(bcryptString, normalizedChars);
   }

   /**
    * Returns the cost factor in use by this instance.
    *
    * @return the integer cost factor used by this instance.
    */
   public int getCostFactor() {
      return costFactor;
   }

   private static byte[] gensalt() {
      final byte[] saltBytes = new byte[BCRYPT_SALT_SIZE];
      secureRandom.nextBytes(saltBytes);
      return saltBytes;
   }

   private static void assertCostFactorValid(int computedCostFactorMin) {
      if (computedCostFactorMin < BCRYPT_COST_FACTOR_MIN || computedCostFactorMin > BCRYPT_COST_FACTOR_MAX) {
         throw new IllegalArgumentException("The cost factor must be between " + BCRYPT_COST_FACTOR_MIN + " and " +
                                                  BCRYPT_COST_FACTOR_MAX + " (inclusive)");
      }
   }
}

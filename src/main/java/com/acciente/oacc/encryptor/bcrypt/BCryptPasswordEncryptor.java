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

   private static final char[] COMPUTED_COST_FACTOR_BENCHMARK_PASSWORD = "honey badger don't care".toCharArray();
   private static final int    COMPUTED_COST_FACTOR_MAX                = BCRYPT_COST_FACTOR_MAX;

   private static final int DEFAULT_COMPUTED_COST_FACTOR_MIN                            = 10;
   private static final int DEFAULT_COMPUTED_COST_FACTOR_MIN_COMPUTE_DURATION_IN_MILLIS = 750;

   private static final PasswordEncoderDecoder passwordEncoderDecoder = new PasswordEncoderDecoder();

   private final int costFactor;

   /**
    * Creates a password encryptor that uses the BCrypt algorithm with the smallest cost factor that causes the BCrypt
    * computation to take at least {@value DEFAULT_COMPUTED_COST_FACTOR_MIN_COMPUTE_DURATION_IN_MILLIS}ms. This method
    * enforces a floor value of {@value DEFAULT_COMPUTED_COST_FACTOR_MIN} for the cost factor, in other words the
    * minimum cost factor used is {@value DEFAULT_COMPUTED_COST_FACTOR_MIN}.
    *
    * @return a {@link BCryptPasswordEncryptor} instance configured as described above.
    */
   public static BCryptPasswordEncryptor getPasswordEncryptor() {
      return getPasswordEncryptorUsingComputedCostFactor(DEFAULT_COMPUTED_COST_FACTOR_MIN_COMPUTE_DURATION_IN_MILLIS,
                                                         DEFAULT_COMPUTED_COST_FACTOR_MIN);
   }

   /**
    * Returns a password encryptor that uses the BCrypt algorithm with the smallest cost factor that causes the BCrypt
    * string computation to take at least the duration specified in the {@code minComputeDurationInMillis} parameter.
    * This method enforces a floor value of {@value DEFAULT_COMPUTED_COST_FACTOR_MIN} for the cost factor, in other words the
    * minimum cost factor used is {@value DEFAULT_COMPUTED_COST_FACTOR_MIN}.
    *
    * @return a {@link BCryptPasswordEncryptor} instance configured as described above.
    */
   public static BCryptPasswordEncryptor getPasswordEncryptorUsingComputedCostFactor(int minComputeDurationInMillis) {
      return getPasswordEncryptorUsingComputedCostFactor(minComputeDurationInMillis,
                                                         DEFAULT_COMPUTED_COST_FACTOR_MIN);
   }

   /**
    * Returns a password encryptor that uses the BCrypt algorithm with the smallest cost factor that causes the BCrypt
    * string computation to take at least the duration specified in the {@code minComputeDurationInMillis} parameter.
    * This method also enforces the floor value for the cost factor specifies in the
    * {@code minComputeDurationInMillis} parameter, in other words the minimum cost factor used is  the duration
    * specified in the {@code minComputeDurationInMillis} parameter.
    *
    * @return a {@link BCryptPasswordEncryptor} instance configured as described above.
    */
   public static BCryptPasswordEncryptor getPasswordEncryptorUsingComputedCostFactor(int minComputeDurationInMillis,
                                                                                     int computedCostFactorMin) {
      assertCostFactorValid(computedCostFactorMin);
      return new BCryptPasswordEncryptor(computeCostFactor(minComputeDurationInMillis,
                                                           computedCostFactorMin));
   }

   /**
    * Returns a password encryptor that uses the BCrypt algorithm with the specified cost factor.
    *
    * @param costFactor the BCrypt cost factor, must be between {@value BCRYPT_COST_FACTOR_MIN} and
    *                   {@value BCRYPT_COST_FACTOR_MAX} (inclusive).
    * @return a {@link BCryptPasswordEncryptor} instance configured as described above.
    */
   public static BCryptPasswordEncryptor getPasswordEncryptorUsingCostFactor(int costFactor) {
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

      final String bcryptString = OpenBSDBCrypt.generate(plainPassword, gensalt(new SecureRandom()), costFactor /* log rounds */);

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

      return OpenBSDBCrypt.checkPassword(bcryptString, plainPassword);
   }

   /**
    * Returns the cost factor in use by this instance. This intended to provide access to the cost factor when it was
    * internally computed and would be otherwise indeterminable.
    *
    * @return an integer cost factor.
    */
   public int getCostFactor() {
      return costFactor;
   }

   static int computeCostFactor(int minComputeDurationInMillis, int computedCostFactorMin) {
      final byte[] salt = gensalt(new SecureRandom());
      for (int costFactor = computedCostFactorMin; costFactor <= COMPUTED_COST_FACTOR_MAX; costFactor++) {
         final long startTime = System.currentTimeMillis();
         OpenBSDBCrypt.generate(COMPUTED_COST_FACTOR_BENCHMARK_PASSWORD, salt, costFactor);
         final long duration = System.currentTimeMillis() - startTime;

         if (duration >= minComputeDurationInMillis) {
            return costFactor;
         }
      }
      return COMPUTED_COST_FACTOR_MAX;
   }

   static byte[] gensalt(SecureRandom secureRandom) {
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

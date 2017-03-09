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
import com.acciente.oacc.encryptor.ReseedingSecureRandom;
import com.acciente.oacc.normalizer.TextNormalizer;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;

import java.io.Serializable;
import java.util.concurrent.TimeUnit;

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

   private static final PasswordEncoderDecoder passwordEncoderDecoder = new PasswordEncoderDecoder();

   private final int                   costFactor;
   private final ReseedingSecureRandom secureRandom;

   /**
    * Returns a password encryptor that uses the BCrypt algorithm with a computed cost factor.
    * The returned password encryptor uses the BCrypt algorithm with the smallest cost factor that causes the BCrypt
    * string computation to take at least the duration specified in the {@code minComputeDurationInMillis} parameter.
    * This method also enforces the floor value for the cost factor specified in the
    * {@code minComputedCostFactor} parameter. In other words, the minimum cost factor used is derived from the duration
    * specified in the {@code minComputeDurationInMillis} parameter.
    *
    * @param minComputedCostFactor the minimum BCrypt cost factor for this encryptor, regardless of the cost factor that
    *                              was computed to take at least the specified amount of time; must be between
    *                              {@value BCRYPT_COST_FACTOR_MIN} and {@value BCRYPT_COST_FACTOR_MAX} (inclusive).
    * @param minComputeDurationInMillis the minimal duration in ms to encrypt a password with BCrypt.
    * @return a {@link BCryptPasswordEncryptor} instance configured as described above.
    * @throws IllegalArgumentException if the specified minimal BCrypt cost factor is not between
    *                                  {@value BCRYPT_COST_FACTOR_MIN} and {@value BCRYPT_COST_FACTOR_MAX} (inclusive).
    */
   public static BCryptPasswordEncryptor newInstance(int minComputedCostFactor, int minComputeDurationInMillis) {
      assertCostFactorValid(minComputedCostFactor);
      return new BCryptPasswordEncryptor(computeCostFactor(minComputedCostFactor, minComputeDurationInMillis));
   }

   /**
    * Returns a password encryptor that uses the BCrypt algorithm with the specified cost factor.
    *
    * @param costFactor the BCrypt cost factor, must be between {@value BCRYPT_COST_FACTOR_MIN} and
    *                   {@value BCRYPT_COST_FACTOR_MAX} (inclusive).
    * @return a {@link BCryptPasswordEncryptor} instance configured as described above.
    * @throws IllegalArgumentException if the specified BCrypt cost factor is not between {@value BCRYPT_COST_FACTOR_MIN}
    *                                  and {@value BCRYPT_COST_FACTOR_MAX} (inclusive).
    */
   public static BCryptPasswordEncryptor newInstance(int costFactor) {
      assertCostFactorValid(costFactor);
      return new BCryptPasswordEncryptor(costFactor);
   }

   private BCryptPasswordEncryptor(int costFactor) {
      this.costFactor = costFactor;
      secureRandom = ReseedingSecureRandom.getInstance();
   }

   @Override
   public String encryptPassword(char[] plainPassword) {
      if (plainPassword == null) {
         return null;
      }
      final char[] normalizedChars = TextNormalizer.getInstance().normalizeToNfc(plainPassword);

      final String bcryptString = OpenBSDBCrypt.generate(normalizedChars, gensalt(secureRandom), costFactor /* log rounds */);

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
    * Returns the cost factor in use by this instance. This allows determining the cost factor when it was
    * internally computed and would be otherwise indeterminable.
    *
    * @return the integer cost factor used by this instance.
    */
   public int getCostFactor() {
      return costFactor;
   }

   private static int computeCostFactor(int computedCostFactorMin, int minComputeDurationInMillis) {
      final byte[] salt = new byte[BCRYPT_SALT_SIZE];
      ReseedingSecureRandom.getInstance().nextBytes(salt);

      for (int costFactor = computedCostFactorMin; costFactor <= COMPUTED_COST_FACTOR_MAX; costFactor++) {
         final long startTime = System.nanoTime();
         OpenBSDBCrypt.generate(COMPUTED_COST_FACTOR_BENCHMARK_PASSWORD, salt, costFactor);
         final long durationInMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startTime);

         if (durationInMillis >= minComputeDurationInMillis) {
            return costFactor;
         }
      }
      return COMPUTED_COST_FACTOR_MAX;
   }

   private static byte[] gensalt(ReseedingSecureRandom secureRandom) {
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

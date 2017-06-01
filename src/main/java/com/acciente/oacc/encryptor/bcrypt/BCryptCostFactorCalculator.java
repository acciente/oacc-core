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

import org.bouncycastle.crypto.generators.OpenBSDBCrypt;

import java.util.concurrent.TimeUnit;

import static com.acciente.oacc.encryptor.bcrypt.BCryptConstants.BCRYPT_COST_FACTOR_MAX;
import static com.acciente.oacc.encryptor.bcrypt.BCryptConstants.BCRYPT_COST_FACTOR_MIN;
import static com.acciente.oacc.encryptor.bcrypt.BCryptConstants.assertCostFactorValid;

/**
 * This class computes the smallest estimated cost factor that causes the BCrypt string computation to take at least
 * a certain specified duration.
 */
public class BCryptCostFactorCalculator {
   private static final char[] COMPUTED_COST_FACTOR_BENCHMARK_PASSWORD = "honey badger don't care".toCharArray();
   private static final int    COMPUTED_COST_JIT_WARMUP_ROUNDS         = 25;

   /**
    * Returns the smallest cost factor that causes the BCrypt string computation to take at least the duration
    * specified in the {@code minComputeDurationInMillis} parameter. This method also enforces the floor value for
    * the cost factor specified in the {@code minComputedCostFactor} parameter. In other words, the minimum cost factor
    * used is derived from the duration specified in the {@code minComputeDurationInMillis} parameter.
    *
    * @param minComputedCostFactor      the minimum BCrypt cost factor for this encryptor, regardless of the cost factor that
    *                                   was computed to take at least the specified amount of time; must be between
    *                                   {@value BCryptConstants#BCRYPT_COST_FACTOR_MIN} and
    *                                   {@value BCryptConstants#BCRYPT_COST_FACTOR_MAX} (inclusive).
    * @param minComputeDurationInMillis the minimal duration in ms to encrypt a password with BCrypt.
    * @return a {@link BCryptPasswordEncryptor} instance configured as described above.
    * @throws IllegalArgumentException if the specified minimal BCrypt cost factor is not between
    *                                  {@value BCryptConstants#BCRYPT_COST_FACTOR_MIN} and
    *                                  {@value BCryptConstants#BCRYPT_COST_FACTOR_MAX} (inclusive).
    */
   public static int calculateCostFactor(int minComputedCostFactor, int minComputeDurationInMillis) {
      assertCostFactorValid(minComputedCostFactor);

      final byte[] salt = BCryptSaltGenerator.generateSalt();

      // first run the BCrypt implementation to cause the JIT to kick in prior to the actual timing run below
      for (int i = 0; i < COMPUTED_COST_JIT_WARMUP_ROUNDS; i++) {
         OpenBSDBCrypt.generate(COMPUTED_COST_FACTOR_BENCHMARK_PASSWORD, salt, BCRYPT_COST_FACTOR_MIN);
      }

      // now do the actual timing run
      for (int costFactor = minComputedCostFactor; costFactor <= BCRYPT_COST_FACTOR_MAX; costFactor++) {
         final long startTime = System.nanoTime();
         OpenBSDBCrypt.generate(COMPUTED_COST_FACTOR_BENCHMARK_PASSWORD, salt, costFactor);
         final long durationInMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startTime);

         if (durationInMillis >= minComputeDurationInMillis) {
            return costFactor;
         }
      }

      return BCRYPT_COST_FACTOR_MAX;
   }
}
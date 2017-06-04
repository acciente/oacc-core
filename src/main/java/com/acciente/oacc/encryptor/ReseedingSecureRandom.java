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
package com.acciente.oacc.encryptor;

import java.io.Serializable;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

public class ReseedingSecureRandom implements RandomNumberGenerator, Serializable {
   private final SecureRandom secureRandom;
   private final long         maxTimeBetweenReseedInSecs;
   private final int          maxNumOfGeneratedValuesBeforeReseed;
   private       long         lastSeedTime;
   private       long         generatedCount;

   public static ReseedingSecureRandom newInstance(int maxNumOfGeneratedValuesBeforeReseed, long maxTimeBetweenReseedInSecs) {
      return new ReseedingSecureRandom(null, maxNumOfGeneratedValuesBeforeReseed, maxTimeBetweenReseedInSecs);
   }

   public static ReseedingSecureRandom newInstance(byte[] seed, int maxNumOfGeneratedValuesBeforeReseed, long maxTimeBetweenReseedInSecs) {
      return new ReseedingSecureRandom(seed, maxNumOfGeneratedValuesBeforeReseed, maxTimeBetweenReseedInSecs);
   }

   public static byte[] getSeed(int seedLength) {
      return SecureRandom.getSeed(seedLength);
   }

   private ReseedingSecureRandom(byte[] seed, int maxNumOfGeneratedValuesBeforeReseed, Long maxTimeBetweenReseedInSecs) {
      assertValidMaxNumOfGeneratedValuesBeforeReseed(maxNumOfGeneratedValuesBeforeReseed);
      assertValidMaxTimeBetweenReseed(maxTimeBetweenReseedInSecs);
      this.maxTimeBetweenReseedInSecs = maxTimeBetweenReseedInSecs;
      this.maxNumOfGeneratedValuesBeforeReseed = maxNumOfGeneratedValuesBeforeReseed;
      if (seed == null) {
         secureRandom = new SecureRandom();
         // call nextBytes() to perform the initial seed
         secureRandom.nextBytes(new byte[8]);
      }
      else {
         secureRandom = new SecureRandom(seed);
      }
      resetCountAndTime();
   }

   public void setSeed(byte[] seed) {
      secureRandom.setSeed(seed);
      resetCountAndTime();
   }

   @Override
   public void nextBytes(byte[] bytes) {
      enforceSeedConstraints();
      secureRandom.nextBytes(bytes);
      generatedCount++;
   }

   private void resetCountAndTime() {
      generatedCount = 0;
      if (maxTimeBetweenReseedInSecs > 0) {
         lastSeedTime = System.nanoTime();
      }
   }

   private void enforceSeedConstraints() {
      if (isSeedingRequired()) {
         setSeed(secureRandom.generateSeed(8));
      }
   }

   private boolean isSeedingRequired() {
      if (generatedCount >= maxNumOfGeneratedValuesBeforeReseed) {
         return true;
      }

      if (maxTimeBetweenReseedInSecs == 0) {
         return false;
      }

      final long secondsSinceSeed = TimeUnit.NANOSECONDS.toSeconds(System.nanoTime() - lastSeedTime);
      return secondsSinceSeed >= maxTimeBetweenReseedInSecs;
   }

   private static void assertValidMaxNumOfGeneratedValuesBeforeReseed(int maxNumOfGeneratedValuesBeforeReseed) {
      if (maxNumOfGeneratedValuesBeforeReseed < 1) {
         throw new IllegalArgumentException("Max number of generated values before reseeding has to be greater than zero");
      }
   }

   private static void assertValidMaxTimeBetweenReseed(long maxTimeBetweenReseedInSecs) {
      if (maxTimeBetweenReseedInSecs < 0) {
         throw new IllegalArgumentException("Max time (in seconds) between reseeding has to be greater than one, or zero, if not applicable");
      }
   }
}

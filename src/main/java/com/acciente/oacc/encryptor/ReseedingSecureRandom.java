package com.acciente.oacc.encryptor;

import java.io.Serializable;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

public class ReseedingSecureRandom implements Serializable {
   private static final long DEFAULT_MAX_TIME_BETWEEN_RESEED_IN_SECS           = TimeUnit.HOURS.toSeconds(1);
   private static final int  DEFAULT_MAX_NUM_OF_GENERATED_VALUES_BEFORE_RESEED = 64;

   private final SecureRandom secureRandom;
   private final Long         maxTimeBetweenReseedInSecs;
   private final int          maxNumOfGeneratedValuesBeforeReseed;
   private       long         lastSeedTime;
   private       long         generatedCount;

   public static ReseedingSecureRandom getInstance() {
      return new ReseedingSecureRandom(null, DEFAULT_MAX_NUM_OF_GENERATED_VALUES_BEFORE_RESEED, DEFAULT_MAX_TIME_BETWEEN_RESEED_IN_SECS);
   }

   public static ReseedingSecureRandom getInstance(int maxNumOfGeneratedValuesBeforeReseed, Long maxTimeBetweenReseedInSecs) {
      return new ReseedingSecureRandom(null, maxNumOfGeneratedValuesBeforeReseed, maxTimeBetweenReseedInSecs);
   }

   public static ReseedingSecureRandom getInstance(byte[] seed) {
      return new ReseedingSecureRandom(seed, DEFAULT_MAX_NUM_OF_GENERATED_VALUES_BEFORE_RESEED, DEFAULT_MAX_TIME_BETWEEN_RESEED_IN_SECS);
   }

   public static ReseedingSecureRandom getInstance(byte[] seed, int maxNumOfGeneratedValuesBeforeReseed, Long maxTimeBetweenReseedInSecs) {
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

   public void nextBytes(byte[] bytes) {
      enforceSeedConstraints();
      secureRandom.nextBytes(bytes);
      generatedCount++;
   }

   private void resetCountAndTime() {
      generatedCount = 0;
      if (maxTimeBetweenReseedInSecs != null) {
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

      if (maxTimeBetweenReseedInSecs == null) {
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

   private static void assertValidMaxTimeBetweenReseed(Long maxTimeBetweenReseedInSecs) {
      if (maxTimeBetweenReseedInSecs != null && maxTimeBetweenReseedInSecs < 1) {
         throw new IllegalArgumentException("Max time (in seconds) between reseeding has to be greater than zero (or null, if not applicable");
      }
   }
}

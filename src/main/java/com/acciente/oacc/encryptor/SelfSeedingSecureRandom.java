package com.acciente.oacc.encryptor;

import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

public class SelfSeedingSecureRandom {
   private static final long DEFAULT_MAX_TIME_BETWEEN_RESEED_IN_SECS           = TimeUnit.HOURS.toSeconds(1);
   private static final int  DEFAULT_MAX_NUM_OF_GENERATED_VALUES_BEFORE_RESEED = 64;

   private final SecureRandom secureRandom;
   private final Long         maxTimeBetweenReseedInSecs;
   private final int          maxNumOfGeneratedValuesBeforeReseed;
   private       long         lastSeedTime;
   private       long         generatedCount;

   public static SelfSeedingSecureRandom getInstance() {
      return new SelfSeedingSecureRandom(DEFAULT_MAX_NUM_OF_GENERATED_VALUES_BEFORE_RESEED, DEFAULT_MAX_TIME_BETWEEN_RESEED_IN_SECS);
   }

   public static SelfSeedingSecureRandom getInstance(int maxNumOfGeneratedValuesBeforeReseed, Long maxTimeBetweenReseedInSecs) {
      return new SelfSeedingSecureRandom(maxNumOfGeneratedValuesBeforeReseed, maxTimeBetweenReseedInSecs);
   }

   public static SelfSeedingSecureRandom getInstance(byte[] seed) {
      return new SelfSeedingSecureRandom(seed, DEFAULT_MAX_NUM_OF_GENERATED_VALUES_BEFORE_RESEED, DEFAULT_MAX_TIME_BETWEEN_RESEED_IN_SECS);
   }

   public static SelfSeedingSecureRandom getInstance(byte[] seed, int maxNumOfGeneratedValuesBeforeReseed, Long maxTimeBetweenReseedInSecs) {
      return new SelfSeedingSecureRandom(seed, maxNumOfGeneratedValuesBeforeReseed, maxTimeBetweenReseedInSecs);
   }

   public static byte[] getSeed(int seedLength) {
      return SecureRandom.getSeed(seedLength);
   }

   private SelfSeedingSecureRandom(int maxNumOfGeneratedValuesBeforeReseed, Long maxTimeBetweenReseedInSecs) {
      this.maxTimeBetweenReseedInSecs = maxTimeBetweenReseedInSecs;
      this.maxNumOfGeneratedValuesBeforeReseed = maxNumOfGeneratedValuesBeforeReseed;
      secureRandom = new SecureRandom();
      // call nextBytes() to perform the initial seed
      secureRandom.nextBytes(new byte[8]);
      resetCountAndTime();
   }

   private SelfSeedingSecureRandom(byte[] seed, int maxNumOfGeneratedValuesBeforeReseed, Long maxTimeBetweenReseedInSecs) {
      this.maxTimeBetweenReseedInSecs = maxTimeBetweenReseedInSecs;
      this.maxNumOfGeneratedValuesBeforeReseed = maxNumOfGeneratedValuesBeforeReseed;
      secureRandom = new SecureRandom(seed);
      resetCountAndTime();
   }

   public void setSeed(byte[] seed) {
      secureRandom.setSeed(seed);
      resetCountAndTime();
   }

   public void setSeed(long seed) {
      secureRandom.setSeed(seed);
      resetCountAndTime();
   }

   public void nextBytes(byte[] bytes) {
      enforceSeedConstraints();
      secureRandom.nextBytes(bytes);
   }

   public int nextInt() {
      enforceSeedConstraints();
      return secureRandom.nextInt();
   }

   public int nextInt(int n) {
      enforceSeedConstraints();
      return secureRandom.nextInt(n);
   }

   public long nextLong() {
      enforceSeedConstraints();
      return secureRandom.nextLong();
   }

   public boolean nextBoolean() {
      enforceSeedConstraints();
      return secureRandom.nextBoolean();
   }

   public float nextFloat() {
      enforceSeedConstraints();
      return secureRandom.nextFloat();
   }

   public double nextDouble() {
      enforceSeedConstraints();
      return secureRandom.nextDouble();
   }

   public double nextGaussian() {
      enforceSeedConstraints();
      return secureRandom.nextGaussian();
   }

   private void enforceSeedConstraints() {
      if (isSeedingRequired()) {
         secureRandom.setSeed(secureRandom.generateSeed(8));
      }
   }

   private void resetCountAndTime() {
      generatedCount = 0;
      if (maxTimeBetweenReseedInSecs != null) {
         lastSeedTime = System.nanoTime();
      }
   }

   private boolean isSeedingRequired() {
      generatedCount++;
      if (generatedCount > maxNumOfGeneratedValuesBeforeReseed) {
         return true;
      }

      if (maxTimeBetweenReseedInSecs == null) {
         return false;
      }

      final long secondsSinceSeed = TimeUnit.NANOSECONDS.toSeconds(System.nanoTime() - lastSeedTime);
      return secondsSinceSeed >= maxTimeBetweenReseedInSecs;
   }
}

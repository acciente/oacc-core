package com.acciente.oacc.encryptor;

import java.security.Provider;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

public class ReseedingSecureRandom extends SecureRandom {
   private static final long DEFAULT_MAX_TIME_BETWEEN_RESEED_IN_SECS           = TimeUnit.HOURS.toSeconds(1);
   private static final int  DEFAULT_MAX_NUM_OF_GENERATED_VALUES_BEFORE_RESEED = 64;

   private final long maxTimeBetweenReseedInSecs;
   private final int  maxNumOfGeneratedValuesBeforeReseed;
   private       long lastSeedTime;
   private       long generatedCount;

   public ReseedingSecureRandom() {
      super();
      this.maxTimeBetweenReseedInSecs = DEFAULT_MAX_TIME_BETWEEN_RESEED_IN_SECS;
      this.maxNumOfGeneratedValuesBeforeReseed = DEFAULT_MAX_NUM_OF_GENERATED_VALUES_BEFORE_RESEED;
      // call nextBytes() to perform the initial seed
      super.nextBytes(new byte[8]);
      resetCountAndTime();
   }

   public ReseedingSecureRandom(int maxNumOfGeneratedValuesBeforeReseed) {
      super();
      this.maxTimeBetweenReseedInSecs = DEFAULT_MAX_TIME_BETWEEN_RESEED_IN_SECS;
      this.maxNumOfGeneratedValuesBeforeReseed = maxNumOfGeneratedValuesBeforeReseed;
      // call nextBytes() to perform the initial seed
      super.nextBytes(new byte[8]);
      resetCountAndTime();
   }

   public ReseedingSecureRandom(int maxNumOfGeneratedValuesBeforeReseed, long maxTimeBetweenReseedInSecs) {
      super();
      this.maxTimeBetweenReseedInSecs = maxTimeBetweenReseedInSecs;
      this.maxNumOfGeneratedValuesBeforeReseed = maxNumOfGeneratedValuesBeforeReseed;
      // call nextBytes() to perform the initial seed
      super.nextBytes(new byte[8]);
      resetCountAndTime();
   }

   public ReseedingSecureRandom(byte[] seed) {
      super(seed);
      this.maxTimeBetweenReseedInSecs = DEFAULT_MAX_TIME_BETWEEN_RESEED_IN_SECS;
      this.maxNumOfGeneratedValuesBeforeReseed = DEFAULT_MAX_NUM_OF_GENERATED_VALUES_BEFORE_RESEED;
      resetCountAndTime();
   }

   public ReseedingSecureRandom(byte[] seed, int maxNumOfGeneratedValuesBeforeReseed) {
      super(seed);
      this.maxTimeBetweenReseedInSecs = DEFAULT_MAX_TIME_BETWEEN_RESEED_IN_SECS;
      this.maxNumOfGeneratedValuesBeforeReseed = maxNumOfGeneratedValuesBeforeReseed;
      resetCountAndTime();
   }

   public ReseedingSecureRandom(byte[] seed, int maxNumOfGeneratedValuesBeforeReseed, long maxTimeBetweenReseedInSecs) {
      super(seed);
      this.maxTimeBetweenReseedInSecs = maxTimeBetweenReseedInSecs;
      this.maxNumOfGeneratedValuesBeforeReseed = maxNumOfGeneratedValuesBeforeReseed;
      resetCountAndTime();
   }

   protected ReseedingSecureRandom(SecureRandomSpi secureRandomSpi, Provider provider) {
      super(secureRandomSpi, provider);
      this.maxTimeBetweenReseedInSecs = DEFAULT_MAX_TIME_BETWEEN_RESEED_IN_SECS;
      this.maxNumOfGeneratedValuesBeforeReseed = DEFAULT_MAX_NUM_OF_GENERATED_VALUES_BEFORE_RESEED;
      // call nextBytes() to perform the initial seed
      super.nextBytes(new byte[8]);
      resetCountAndTime();
   }

   @Override
   public synchronized void setSeed(byte[] seed) {
      super.setSeed(seed);
      resetCountAndTime();
   }

   @Override
   public void setSeed(long seed) {
      super.setSeed(seed);
      resetCountAndTime();
   }

   @Override
   public synchronized void nextBytes(byte[] bytes) {
      enforceSeedConstraints();
      super.nextBytes(bytes);
   }

   @Override
   public int nextInt() {
      enforceSeedConstraints();
      return super.nextInt();
   }

   @Override
   public int nextInt(int n) {
      enforceSeedConstraints();
      return super.nextInt(n);
   }

   @Override
   public long nextLong() {
      enforceSeedConstraints();
      return super.nextLong();
   }

   @Override
   public boolean nextBoolean() {
      enforceSeedConstraints();
      return super.nextBoolean();
   }

   @Override
   public float nextFloat() {
      enforceSeedConstraints();
      return super.nextFloat();
   }

   @Override
   public double nextDouble() {
      enforceSeedConstraints();
      return super.nextDouble();
   }

   @Override
   public synchronized double nextGaussian() {
      enforceSeedConstraints();
      return super.nextGaussian();
   }

   private void enforceSeedConstraints() {
      if (isSeedingRequired()) {
         setSeed(generateSeed(8));
      }
   }

   private void resetCountAndTime() {
      generatedCount = 0;
      lastSeedTime = System.nanoTime();
   }

   private boolean isSeedingRequired() {
      generatedCount++;
      if (generatedCount > maxNumOfGeneratedValuesBeforeReseed) {
         return true;
      }

      final long secondsSinceSeed = TimeUnit.NANOSECONDS.toSeconds(System.nanoTime() - lastSeedTime);
      return secondsSinceSeed >= maxTimeBetweenReseedInSecs;
//      final long millisSinceSeed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - lastSeedTime);
//      return millisSinceSeed >= TimeUnit.SECONDS.toMillis(maxTimeBetweenReseedInSecs);
   }
}

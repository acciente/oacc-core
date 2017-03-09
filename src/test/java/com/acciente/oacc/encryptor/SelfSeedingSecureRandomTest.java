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

import org.bouncycastle.util.Arrays;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class SelfSeedingSecureRandomTest {

   private static final int  SEED_LENGTH                      = 8;
   private static final int  NUM_OF_RANDOM_BYTES              = 20; // should be >= 20 for testing, to avoid getting remainder of prev value
   private static final long MAX_TIME_BETWEEN_RESEEDS_IN_SECS = 30;

   @Test
   public void sameSeedGeneratesSameBytes() throws Exception {
      final byte[] seedBytes = SelfSeedingSecureRandom.getSeed(SEED_LENGTH);
      final byte[] randomBytes1 = new byte[NUM_OF_RANDOM_BYTES];
      final byte[] randomBytes2 = new byte[NUM_OF_RANDOM_BYTES];
      final SelfSeedingSecureRandom prng1 = SelfSeedingSecureRandom.getInstance(seedBytes);
      final SelfSeedingSecureRandom prng2 = SelfSeedingSecureRandom.getInstance(seedBytes);

      prng1.nextBytes(randomBytes1);
      prng2.nextBytes(randomBytes2);

      assertThat(randomBytes1, equalTo(randomBytes2));
   }

   @Test
   public void sameAsSecureRandom() throws Exception {
      final byte[] seedBytes = SelfSeedingSecureRandom.getSeed(SEED_LENGTH);
      final byte[] reseedingRandomBytes = new byte[NUM_OF_RANDOM_BYTES];
      final byte[] secureRandomBytes = new byte[NUM_OF_RANDOM_BYTES];
      final SelfSeedingSecureRandom reseedingSecureRandom = SelfSeedingSecureRandom.getInstance(seedBytes);
      final SecureRandom secureRandom = new SecureRandom(seedBytes);

      reseedingSecureRandom.nextBytes(reseedingRandomBytes);
      secureRandom.nextBytes(secureRandomBytes);

      assertThat(reseedingRandomBytes, equalTo(secureRandomBytes));
   }

   @Test
   public void differentSeedGeneratesDifferentBytes() throws Exception {
      final byte[] seedBytes1 = SelfSeedingSecureRandom.getSeed(SEED_LENGTH);
      final byte[] seedBytes2 = Arrays.reverse(seedBytes1);
      final byte[] randomBytes1 = new byte[NUM_OF_RANDOM_BYTES];
      final byte[] randomBytes2 = new byte[NUM_OF_RANDOM_BYTES];
      final SelfSeedingSecureRandom prng1 = SelfSeedingSecureRandom.getInstance(seedBytes1);
      final SelfSeedingSecureRandom prng2 = SelfSeedingSecureRandom.getInstance(seedBytes2);

      prng1.nextBytes(randomBytes1);
      prng2.nextBytes(randomBytes2);

      assertThat(randomBytes1, not(equalTo(randomBytes2)));
   }

   @Test
   public void invalidMaxNumOfGeneratedValuesBeforeReseedThrowsException() throws Exception {
      final int invalidMaxNumOfGeneratedValuesBeforeReseed = 0;
      try {
         SelfSeedingSecureRandom.getInstance(invalidMaxNumOfGeneratedValuesBeforeReseed, null);
         fail("Invalid max number of values generated before reseeding should have failed;");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("max number of generated values"));
      }
      try {
         final byte[] seedBytes = SelfSeedingSecureRandom.getSeed(SEED_LENGTH);
         SelfSeedingSecureRandom.getInstance(seedBytes, invalidMaxNumOfGeneratedValuesBeforeReseed, null);
         fail("Invalid max number of values generated before reseeding should have failed;");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("max number of generated values"));
      }
   }

   @Test
   public void invalidMaxTimeBetweenReseedThrowsException() throws Exception {
      final long invalidMaxTimeBetweenReseedInSecs = 0;
      try {
         SelfSeedingSecureRandom.getInstance(32, invalidMaxTimeBetweenReseedInSecs);
         fail("Invalid max time between reseeding should have failed;");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("max time"));
      }
      try {
         final byte[] seedBytes = SelfSeedingSecureRandom.getSeed(SEED_LENGTH);
         SelfSeedingSecureRandom.getInstance(seedBytes, 32, invalidMaxTimeBetweenReseedInSecs);
         fail("Invalid max time between reseeding should have failed;");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("max time"));
      }
   }

   @Test
   public void reseedsAfterMaxNumOfValuesGenerated() throws Exception {
      final byte[] seedBytes = SelfSeedingSecureRandom.getSeed(SEED_LENGTH);
      final byte[] reseedingRandomBytes = new byte[NUM_OF_RANDOM_BYTES];
      final byte[] staticRandomBytes = new byte[NUM_OF_RANDOM_BYTES];
      final int maxValuesBeforeReseed = 3;
      final SelfSeedingSecureRandom reseedingPrng = SelfSeedingSecureRandom.getInstance(seedBytes, maxValuesBeforeReseed, MAX_TIME_BETWEEN_RESEEDS_IN_SECS);
      final SecureRandom staticPrng = new SecureRandom(seedBytes);

      // first n passes
      for (int i = 0; i < maxValuesBeforeReseed; i++) {
         reseedingPrng.nextBytes(reseedingRandomBytes);
         staticPrng.nextBytes(staticRandomBytes);
         // assertThat(reseedingRandomBytes, equalTo(staticRandomBytes));
      }

      // after reseeding
      staticPrng.nextBytes(staticRandomBytes);
      reseedingPrng.nextBytes(reseedingRandomBytes);
      assertThat(reseedingRandomBytes, not(equalTo(staticRandomBytes)));
   }

   @Test
   public void reseedsAfterMaxNumOfValuesGeneratedWithoutMaxTime() throws Exception {
      final byte[] seedBytes = SelfSeedingSecureRandom.getSeed(SEED_LENGTH);
      final byte[] reseedingRandomBytes = new byte[NUM_OF_RANDOM_BYTES];
      final byte[] staticRandomBytes = new byte[NUM_OF_RANDOM_BYTES];
      final int maxValuesBeforeReseed = 3;
      final SelfSeedingSecureRandom reseedingPrng = SelfSeedingSecureRandom.getInstance(seedBytes, maxValuesBeforeReseed, null);
      final SecureRandom staticPrng = new SecureRandom(seedBytes);

      // first n passes
      for (int i = 0; i < maxValuesBeforeReseed; i++) {
         reseedingPrng.nextBytes(reseedingRandomBytes);
         staticPrng.nextBytes(staticRandomBytes);
         // assertThat(reseedingRandomBytes, equalTo(staticRandomBytes));
      }

      // after reseeding
      staticPrng.nextBytes(staticRandomBytes);
      reseedingPrng.nextBytes(reseedingRandomBytes);
      assertThat(reseedingRandomBytes, not(equalTo(staticRandomBytes)));
   }

   @Test
   public void reseedsAfterMaxTimeElapsed() throws Exception {
      final byte[] seedBytes = SelfSeedingSecureRandom.getSeed(SEED_LENGTH);
      final byte[] reseedingRandomBytes = new byte[NUM_OF_RANDOM_BYTES];
      final byte[] staticRandomBytes = new byte[NUM_OF_RANDOM_BYTES];
      final int maxValuesBeforeReseed = 64;
      final long maxTimeBeforeReseedInSecs = 1;
      final SelfSeedingSecureRandom reseedingPrng
            = SelfSeedingSecureRandom.getInstance(seedBytes, maxValuesBeforeReseed, maxTimeBeforeReseedInSecs);
      final SecureRandom staticPrng = new SecureRandom(seedBytes);

      // first pass
      reseedingPrng.nextBytes(reseedingRandomBytes);
      staticPrng.nextBytes(staticRandomBytes);
      // assertThat(reseedingRandomBytes, equalTo(staticRandomBytes));

      // second pass
      staticPrng.nextBytes(staticRandomBytes);

      // wait for the max time
      TimeUnit.MILLISECONDS.sleep(TimeUnit.SECONDS.toMillis(maxTimeBeforeReseedInSecs) + 10);

      reseedingPrng.nextBytes(reseedingRandomBytes);
      assertThat(reseedingRandomBytes, not(equalTo(staticRandomBytes)));
   }

   @Test
   public void seedingResetsGeneratedValueCounter() throws Exception {
      final byte[] seedBytes = SelfSeedingSecureRandom.getSeed(SEED_LENGTH);
      final byte[] reseedingRandomBytes = new byte[NUM_OF_RANDOM_BYTES];
      final byte[] staticRandomBytes = new byte[NUM_OF_RANDOM_BYTES];
      final int maxValuesBeforeReseed = 3;
      final SelfSeedingSecureRandom reseedingPrng
            = SelfSeedingSecureRandom.getInstance(seedBytes, maxValuesBeforeReseed, MAX_TIME_BETWEEN_RESEEDS_IN_SECS);
      final SecureRandom staticPrng = new SecureRandom(seedBytes);

      // first pass
      reseedingPrng.nextBytes(reseedingRandomBytes);
      staticPrng.nextBytes(staticRandomBytes);

      // reseed
      final byte[] reseedBytes = SelfSeedingSecureRandom.getSeed(SEED_LENGTH);
      reseedingPrng.setSeed(reseedBytes);
      staticPrng.setSeed(reseedBytes);

      // first n passes after reseeding
      for (int i = 0; i < maxValuesBeforeReseed; i++) {
         reseedingPrng.nextBytes(reseedingRandomBytes);
         staticPrng.nextBytes(staticRandomBytes);
         assertThat(reseedingRandomBytes, equalTo(staticRandomBytes));
      }

      reseedingPrng.nextBytes(reseedingRandomBytes);
      staticPrng.nextBytes(staticRandomBytes);
      assertThat(reseedingRandomBytes, not(equalTo(staticRandomBytes)));
   }

   @Test
   public void seedingResetsTimer() throws Exception {
      final byte[] seedBytes = SelfSeedingSecureRandom.getSeed(SEED_LENGTH);
      final byte[] reseedingRandomBytes = new byte[NUM_OF_RANDOM_BYTES];
      final byte[] staticRandomBytes = new byte[NUM_OF_RANDOM_BYTES];
      final int maxValuesBeforeReseed = 64;
      final long maxTimeBeforeReseedInSecs = 1;
      final SelfSeedingSecureRandom reseedingPrng
            = SelfSeedingSecureRandom.getInstance(seedBytes, maxValuesBeforeReseed, maxTimeBeforeReseedInSecs);
      final SecureRandom staticPrng = new SecureRandom(seedBytes);

      // first pass
      reseedingPrng.nextBytes(reseedingRandomBytes);
      staticPrng.nextBytes(staticRandomBytes);

      // wait for 3/4 the max time
      TimeUnit.MILLISECONDS.sleep(3 * TimeUnit.SECONDS.toMillis(maxTimeBeforeReseedInSecs) / 4);

      // reseed
      final byte[] reseedBytes = SelfSeedingSecureRandom.getSeed(SEED_LENGTH);
      reseedingPrng.setSeed(reseedBytes);
      staticPrng.setSeed(reseedBytes);

      staticPrng.nextBytes(staticRandomBytes);

      // wait for another 3/4 of the max time (total elapsed time since first pass: 1.5x max time)
      TimeUnit.MILLISECONDS.sleep(3 * TimeUnit.SECONDS.toMillis(maxTimeBeforeReseedInSecs) / 4);

      // first pass after reseeding
      reseedingPrng.nextBytes(reseedingRandomBytes);
      assertThat(reseedingRandomBytes, equalTo(staticRandomBytes));

      // wait for another 1/2 of the max time (elapsed time since reseed: 1.25x max time)
      TimeUnit.MILLISECONDS.sleep(TimeUnit.SECONDS.toMillis(maxTimeBeforeReseedInSecs) / 2);

      reseedingPrng.nextBytes(reseedingRandomBytes);
      staticPrng.nextBytes(staticRandomBytes);
      assertThat(reseedingRandomBytes, not(equalTo(staticRandomBytes)));
   }
}
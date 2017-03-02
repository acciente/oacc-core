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

import org.junit.Test;

import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.junit.Assert.assertThat;

public class ReseedingSecureRandomTest {

   public static final int SEED_LENGTH = 8;
   public static final int NUM_OF_RANDOM_BYTES = SEED_LENGTH * 2;

   @Test
   public void sameSeedGeneratesSameBytes() throws Exception {
      final byte[] seedBytes = ReseedingSecureRandom.getSeed(SEED_LENGTH);
      final byte[] randomBytes1 = new byte[NUM_OF_RANDOM_BYTES];
      final byte[] randomBytes2 = new byte[NUM_OF_RANDOM_BYTES];
      final ReseedingSecureRandom prng1 = new ReseedingSecureRandom(seedBytes);
      final ReseedingSecureRandom prng2 = new ReseedingSecureRandom(seedBytes);

      prng1.nextBytes(randomBytes1);
      prng2.nextBytes(randomBytes2);

      assertThat(randomBytes1, equalTo(randomBytes2));
   }

   @Test
   public void sameAsSecureRandom() throws Exception {
      final byte[] seedBytes = ReseedingSecureRandom.getSeed(SEED_LENGTH);
      final byte[] reseedingRandomBytes = new byte[NUM_OF_RANDOM_BYTES];
      final byte[] secureRandomBytes = new byte[NUM_OF_RANDOM_BYTES];
      final ReseedingSecureRandom reseedingSecureRandom = new ReseedingSecureRandom(seedBytes);
      final SecureRandom secureRandom = new SecureRandom(seedBytes);

      reseedingSecureRandom.nextBytes(reseedingRandomBytes);
      secureRandom.nextBytes(secureRandomBytes);

      assertThat(reseedingRandomBytes, equalTo(secureRandomBytes));
   }

   @Test
   public void differentSeedGeneratesDifferentBytes() throws Exception {
      final byte[] seedBytes1 = ReseedingSecureRandom.getSeed(SEED_LENGTH);
      final byte[] seedBytes2 = ReseedingSecureRandom.getSeed(SEED_LENGTH);
      final byte[] randomBytes1 = new byte[NUM_OF_RANDOM_BYTES];
      final byte[] randomBytes2 = new byte[NUM_OF_RANDOM_BYTES];
      final ReseedingSecureRandom prng1 = new ReseedingSecureRandom(seedBytes1);
      final ReseedingSecureRandom prng2 = new ReseedingSecureRandom(seedBytes2);

      prng1.nextBytes(randomBytes1);
      prng2.nextBytes(randomBytes2);

      assertThat(randomBytes1, not(equalTo(randomBytes2)));
   }

   @Test
   public void reseedsAfterMaxNumOfValuesGenerated() throws Exception {
      final byte[] seedBytes = ReseedingSecureRandom.getSeed(SEED_LENGTH);
      final byte[] reseedingRandomBytes = new byte[NUM_OF_RANDOM_BYTES];
      final byte[] staticRandomBytes = new byte[NUM_OF_RANDOM_BYTES];
      final int maxValuesBeforeReseed = 1;
      final ReseedingSecureRandom reseedingPrng = new ReseedingSecureRandom(seedBytes, maxValuesBeforeReseed);
      final ReseedingSecureRandom staticPrng = new ReseedingSecureRandom(seedBytes, maxValuesBeforeReseed * 4);

      // first pass
      reseedingPrng.nextBytes(reseedingRandomBytes);
      staticPrng.nextBytes(staticRandomBytes);
      // assertThat(reseedingRandomBytes, equalTo(staticRandomBytes));

      // second pass
      staticPrng.nextBytes(staticRandomBytes);
      reseedingPrng.nextBytes(reseedingRandomBytes);
      assertThat(reseedingRandomBytes, not(equalTo(staticRandomBytes)));
   }

   @Test
   public void reseedsAfterMaxTimeElapsed() throws Exception {
      final byte[] seedBytes = ReseedingSecureRandom.getSeed(SEED_LENGTH);
      final byte[] reseedingRandomBytes = new byte[NUM_OF_RANDOM_BYTES];
      final byte[] staticRandomBytes = new byte[NUM_OF_RANDOM_BYTES];
      final int maxValuesBeforeReseed = 64;
      final long maxTimeBeforeReseedInSecs = 1;
      final ReseedingSecureRandom reseedingPrng
            = new ReseedingSecureRandom(seedBytes, maxValuesBeforeReseed, maxTimeBeforeReseedInSecs);
      final ReseedingSecureRandom staticPrng
            = new ReseedingSecureRandom(seedBytes,
                                        maxValuesBeforeReseed * 4,
                                        maxTimeBeforeReseedInSecs * 4);

      // first pass
      reseedingPrng.nextBytes(reseedingRandomBytes);
      staticPrng.nextBytes(staticRandomBytes);
      // assertThat(reseedingRandomBytes, equalTo(staticRandomBytes));

      // second pass
      staticPrng.nextBytes(staticRandomBytes);

      // wait for the max time
//      TimeUnit.SECONDS.sleep(maxTimeBeforeReseedInSecs);
      TimeUnit.MILLISECONDS.sleep(TimeUnit.SECONDS.toMillis(maxTimeBeforeReseedInSecs) + 10);

      reseedingPrng.nextBytes(reseedingRandomBytes);
      assertThat(reseedingRandomBytes, not(equalTo(staticRandomBytes)));
   }
}
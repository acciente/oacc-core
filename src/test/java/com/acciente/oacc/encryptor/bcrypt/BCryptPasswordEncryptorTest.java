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

import org.junit.Test;

import java.util.concurrent.TimeUnit;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.nullValue;
import static org.hamcrest.core.StringStartsWith.startsWith;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class BCryptPasswordEncryptorTest {
   private final BCryptPasswordEncryptor encryptor = BCryptPasswordEncryptor.newInstance(4);

   @Test
   public void getEncryptorDoesNotAcceptCostFactorBelowMin() throws Exception {
      try {
         BCryptPasswordEncryptor.newInstance(3);
         fail("getting BCrypt password encryptor with cost factor below the minimum should fail");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("cost factor must be"));
      }
   }

   @Test
   public void getEncryptorDoesNotAcceptCostFactorAboveMax() throws Exception {
      try {
         BCryptPasswordEncryptor.newInstance(32);
         fail("getting BCrypt password encryptor with cost factor above the maximum should fail");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("cost factor must be"));
      }
   }

   @Test
   public void getEncryptorUsesSpecifiedCostFactor() throws Exception {
      final int costFactor = 5;
      final BCryptPasswordEncryptor passwordEncryptor
            = BCryptPasswordEncryptor.newInstance(costFactor);

      assertThat(passwordEncryptor.getCostFactor(), is(costFactor));
   }

   @Test
   public void getComputedEncryptorDoesNotAcceptCostFactorBelowMin() throws Exception {
      try {
         final int minComputeDuration = 100;
         BCryptPasswordEncryptor.newInstance(3, minComputeDuration);
         fail("getting BCrypt password encryptor with minimum computed cost factor below the minimum should fail");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("cost factor must be"));
      }
   }

   @Test
   public void getComputedEncryptorDoesNotAcceptCostFactorAboveMax() throws Exception {
      try {
         final int minComputeDuration = 100;
         BCryptPasswordEncryptor.newInstance(32, minComputeDuration);
         fail("getting BCrypt password encryptor with minimum computed cost factor above the maximum should fail");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("cost factor must be"));
      }
   }

   @Test
   public void getComputedEncryptorComputesCostFactor() throws Exception {
      final int minComputeDuration = 100;
      final int minCostFactor = 4;
      final BCryptPasswordEncryptor passwordEncryptor
            = BCryptPasswordEncryptor.newInstance(minCostFactor, minComputeDuration);

      assertTrue(passwordEncryptor.getCostFactor() > minCostFactor);
   }

   @Test
   public void getComputedEncryptorRunsAtLeastForMinComputeDuration() throws Exception {
      final int minComputeDurationInMs = 250;
      final int minCostFactor = 4;
      final BCryptPasswordEncryptor passwordEncryptor
            = BCryptPasswordEncryptor.newInstance(minCostFactor, minComputeDurationInMs);
      final char[] password = "opensesame".toCharArray();

      final long startTime = System.nanoTime();
      passwordEncryptor.encryptPassword(password);
      final long endTime = System.nanoTime();
      final long durationInMs = TimeUnit.NANOSECONDS.toMillis(endTime - startTime);

      assertTrue(durationInMs > minComputeDurationInMs);
   }

   @Test
   public void encryptNullPassword() throws Exception {
      final char[] testPassword = null;

      final String encryptedPassword = encryptor.encryptPassword(testPassword);

      assertThat(encryptedPassword, is(nullValue()));
   }

   @Test
   public void encryptPasswordDifferentHashesForSamePassword() throws Exception {
      final char[] testPassword = "SomePasswordHere".toCharArray();

      final String encryptedPasswordPass1 = encryptor.encryptPassword(testPassword);
      final String encryptedPasswordPass2 = encryptor.encryptPassword(testPassword);

      assertThat(encryptedPasswordPass1, not(equalTo(encryptedPasswordPass2)));
   }

   @Test
   public void encryptPasswordHeaderMarkerPresent() throws Exception {
      final char[] testPassword = "SomePasswordHere".toCharArray();

      final String encryptedPasswordPass = encryptor.encryptPassword(testPassword);

      assertThat(encryptedPasswordPass, startsWith(BCryptPasswordEncryptor.NAME + ":"));
   }

   @Test
   public void checkNullPasswords() throws Exception {
      final char[] testPassword = null;

      final String encryptedPassword = encryptor.encryptPassword(testPassword);

      assertThat(encryptor.checkPassword(testPassword, encryptedPassword), is(true));
   }

   @Test
   public void checkNullPassword() throws Exception {
      final char[] testPassword = "SomePasswordHere".toCharArray();

      final String encryptedPassword = encryptor.encryptPassword(testPassword);

      assertThat(encryptor.checkPassword(null, encryptedPassword), is(false));
   }

   @Test
   public void checkNullStoredPassword() throws Exception {
      final char[] testPassword = "SomePasswordHere".toCharArray();

      assertThat(encryptor.checkPassword(testPassword, null), is(false));
   }

   @Test
   public void checkPassword() throws Exception {
      final char[] testPassword = "SomePasswordHere".toCharArray();

      final String encryptedPasswordPass1 = encryptor.encryptPassword(testPassword);

      assertThat(encryptor.checkPassword(testPassword, encryptedPasswordPass1), is(true));
   }

   @Test
   public void checkNormalizedPassword() throws Exception {
      final char[] combiningSequencePwd = new char[]{'A', 0x30a}; // A, combining-ring-above
      final char[] singleCharacterPwd = new char[]{0x00c5};       // latin-capital-a-with-ring-above (Å)

      final String encryptedPasswordPass1 = encryptor.encryptPassword(combiningSequencePwd);

      assertThat(encryptor.checkPassword(singleCharacterPwd, encryptedPasswordPass1), is(true));
   }
}
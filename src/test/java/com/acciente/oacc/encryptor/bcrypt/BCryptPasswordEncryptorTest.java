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
   public void newInstanceDoesNotAcceptCostFactorBelowMin() throws Exception {
      try {
         BCryptPasswordEncryptor.newInstance(3);
         fail("getting BCrypt password encryptor with cost factor below the minimum should fail");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("cost factor must be"));
      }
   }

   @Test
   public void newInstanceDoesNotAcceptCostFactorAboveMax() throws Exception {
      try {
         BCryptPasswordEncryptor.newInstance(32);
         fail("getting BCrypt password encryptor with cost factor above the maximum should fail");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("cost factor must be"));
      }
   }

   @Test
   public void newInstanceUsesSpecifiedCostFactor() throws Exception {
      final int costFactor = 5;
      final BCryptPasswordEncryptor passwordEncryptor
            = BCryptPasswordEncryptor.newInstance(costFactor);

      assertThat(passwordEncryptor.getCostFactor(), is(costFactor));
   }

   @Test
   public void newInstanceUsingComputedCostFactorDoesNotAcceptCostFactorBelowMin() throws Exception {
      try {
         final int minComputeDuration = 100;
         BCryptPasswordEncryptor.newInstance(BCryptCostFactorCalculator.calculateCostFactor(3, minComputeDuration));
         fail("getting BCrypt password encryptor with minimum computed cost factor below the minimum should fail");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("cost factor must be"));
      }
   }

   @Test
   public void newInstanceUsingComputedCostFactorDoesNotAcceptCostFactorAboveMax() throws Exception {
      try {
         final int minComputeDuration = 100;
         BCryptPasswordEncryptor.newInstance(BCryptCostFactorCalculator.calculateCostFactor(32, minComputeDuration));
         fail("getting BCrypt password encryptor with minimum computed cost factor above the maximum should fail");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("cost factor must be"));
      }
   }

   @Test
   public void newInstanceUsingComputedCostFactorComputesCostFactor() throws Exception {
      final int minComputeDuration = 100;
      final int minCostFactor = 4;
      final BCryptPasswordEncryptor passwordEncryptor
            = BCryptPasswordEncryptor.newInstance(
                  BCryptCostFactorCalculator.calculateCostFactor(minCostFactor, minComputeDuration));

      assertTrue(passwordEncryptor.getCostFactor() > minCostFactor);
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
   public void encryptPasswordDifferentHashesForLongPasswords() throws Exception {
      // bcrypt only uses the **first 72 chars** of the plaintext to generate a hash, because
      // it is meant to be used on low-entropy (e.g. human-memorable password) secrets, but
      // with a deliberately slow hashing process as an added defense
      // - source:(http://security.stackexchange.com/a/21537/23744)
      //
      // bcrypt authors Provos & Mazières mention passwords "up to 56 bytes" even though
      // the algorithm itself makes use of a 72 byte initial value because they may have
      // been motivated by the following statement from Bruce Schneier's original specification
      // of Blowfish:
      // **"The 448 [bit] limit on the key size ensures that the[sic] every bit of every subkey
      // depends on every bit of the key."**
      // - source:(https://en.wikipedia.org/wiki/Bcrypt)
      //
      // in practice, this should **not affect** us because the passwords are salted!
      final String prefix72char = "123456789.123456789.123456789.123456789.123456789.123456789.123456789.12";
      final char[] longPassword1 = (prefix72char + "-foo").toCharArray();
      final char[] longPassword2 = (prefix72char + "-bar").toCharArray();

      final String encryptedPasswordPass1 = encryptor.encryptPassword(longPassword1);
      final String encryptedPasswordPass2 = encryptor.encryptPassword(longPassword2);

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
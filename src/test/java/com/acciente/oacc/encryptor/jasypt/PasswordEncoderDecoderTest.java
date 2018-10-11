/*
 * Copyright 2009-2018, Acciente LLC
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

package com.acciente.oacc.encryptor.jasypt;

import org.jasypt.contrib.org.apache.commons.codec_1_3.binary.Base64;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.StringEndsWith.endsWith;
import static org.hamcrest.core.StringStartsWith.startsWith;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class PasswordEncoderDecoderTest {
   private final PasswordEncoderDecoder encoderDecoder = new PasswordEncoderDecoder();

   private static final Base64 base64    = new Base64();
   private static final String MARKER    = "jasypt:";
   private static final String DELIMITER = "$";

   private static final String DECODED_PASSWORD_ALGORITHM       = "TEST-algorithm";
   private static final int    DECODED_PASSWORD_ITERATIONS      = 1243322;
   private static final int    DECODED_PASSWORD_SALT_SIZE_BYTES = 33;
   private static final byte[] DECODED_PASSWORD_DIGEST          = "TEST-digest".getBytes();

   private static final String ENCODED_PASSWORD = MARKER +
         DECODED_PASSWORD_ALGORITHM + DELIMITER +
         DECODED_PASSWORD_ITERATIONS + DELIMITER +
         DECODED_PASSWORD_SALT_SIZE_BYTES + DELIMITER +
         new String(base64.encode(DECODED_PASSWORD_DIGEST), StandardCharsets.US_ASCII);

   private static final String ENCODED_LEGACY_PASSWORD =
         new String(base64.encode(DECODED_PASSWORD_DIGEST), StandardCharsets.US_ASCII);

   private static final String ENCODED_INVALID_PASSWORD = "jasypt:(the-content-in-parens-does-not-matter)";

   @Test
   public void testEncodePassword() throws Exception {
      final String encodedPassword = encoderDecoder.encode(DECODED_PASSWORD_ALGORITHM,
                                                           DECODED_PASSWORD_ITERATIONS,
                                                           DECODED_PASSWORD_SALT_SIZE_BYTES,
                                                           DECODED_PASSWORD_DIGEST);
      assertThat(encodedPassword, is(ENCODED_PASSWORD));
   }

   @Test
   public void testDecodePassword() throws Exception {
      final DecodedPassword decodedPassword = encoderDecoder.decode(ENCODED_PASSWORD);

      assertThat(decodedPassword.getAlgorithm(), is(DECODED_PASSWORD_ALGORITHM));
      assertThat(decodedPassword.getIterations(), is(DECODED_PASSWORD_ITERATIONS));
      assertThat(decodedPassword.getSaltSizeBytes(), is(DECODED_PASSWORD_SALT_SIZE_BYTES));
      assertThat(decodedPassword.getDigest(), is(DECODED_PASSWORD_DIGEST));
   }

   @Test
   public void testDecodeLegacyPassword() throws Exception {
      try {
         encoderDecoder.decode(ENCODED_LEGACY_PASSWORD);
         fail("Expected an IllegalArgumentException");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage(), startsWith("Unexpected marker for Jasypt password:"));
      }
   }

   @Test
   public void decodePasswordCheckExceptionDoesNotContainFullEncodedPassword() throws Exception {
      try {
         encoderDecoder.decode(ENCODED_INVALID_PASSWORD);
         fail("Expected IllegalArgumentException, but not thrown");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage(), endsWith(ENCODED_INVALID_PASSWORD.substring(0, MARKER.length())));
      }
   }
}